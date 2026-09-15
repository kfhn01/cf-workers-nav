const DEFAULT_USER = 'testUser';
const DEFAULT_IMGAPI = 'https://api.xinac.net/icon/?url=';
let USE_DEFAULT_IMGAPI = true;

function base64UrlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlEncodeUint8(arr) {
    const str = String.fromCharCode(...arr);
    return base64UrlEncode(str);
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

async function createJWT(payload, secret) {
    const encoder = new TextEncoder();
    const header = { alg: 'HS256', typ: 'JWT' };
    const headerEncoded = base64UrlEncode(JSON.stringify(header));
    const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
    const toSign = encoder.encode(`${headerEncoded}.${payloadEncoded}`);

    const key = await crypto.subtle.importKey(
        'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, toSign);
    const signatureEncoded = base64UrlEncodeUint8(new Uint8Array(signature));

    return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
}

async function validateJWT(token, secret) {
    try {
        const encoder = new TextEncoder();
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        const [headerEncoded, payloadEncoded, signature] = parts;
        const data = encoder.encode(`${headerEncoded}.${payloadEncoded}`);

        const key = await crypto.subtle.importKey(
            'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );

        const expectedSigBuffer = await crypto.subtle.sign('HMAC', key, data);
        const expectedSig = base64UrlEncodeUint8(new Uint8Array(expectedSigBuffer));

        if (signature !== expectedSig) return null;

        const payloadStr = base64UrlDecode(payloadEncoded);
        return JSON.parse(payloadStr);
    } catch (e) {
        return null;
    }
}

function parseCookie(cookieHeader) {
    const cookies = {};
    if (!cookieHeader) return cookies;
    cookieHeader.split(';').forEach(cookie => {
        const [name, value] = cookie.trim().split('=');
        cookies[name] = decodeURIComponent(value);
    });
    return cookies;
}

async function validateServerToken(authHeader, env) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { isValid: false, status: 401, response: { error: 'Unauthorized', message: '未登录' } };
    }
    const token = authHeader.slice(7);
    
    const payload = await validateJWT(token, env.JWT_SECRET);
    
    if (!payload) {
        return { isValid: false, status: 401, response: { error: 'Invalid', message: 'Token无效' } };
    }
    
    if (payload.exp < Math.floor(Date.now() / 1000)) {
        return { isValid: false, status: 401, response: { error: 'Expired', message: 'Token过期' } };
    }

    if (payload.type !== 'access') {
        return { isValid: false, status: 403, response: { error: 'Forbidden', message: '令牌类型错误' } };
    }

    return { isValid: true, payload };
}

function normalizeCategories(categories) {
    for (const key in categories) {
        if (Array.isArray(categories[key])) {
            categories[key] = { isHidden: false, links: categories[key] };
        }
    }
    return categories;
}

const corsHeaders = {
    'Access-Control-Allow-Origin': '*', 
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cookie',
    'Access-Control-Allow-Credentials': 'true' 
};

async function fetchBestIcon(targetUrl) {
    const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    };

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); 
        
        const response = await fetch(targetUrl, {
            headers: headers,
            redirect: 'follow',
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) throw new Error('Site unreachable');

        let iconUrl = null;
        
        const rewriter = new HTMLRewriter()
            .on('link[rel="apple-touch-icon"]', { 
                element(e) {
                    if (!iconUrl) {
                        const href = e.getAttribute('href');
                        if (href) iconUrl = href;
                    }
                }
            })
            .on('link[rel~="icon"]', {
                element(e) {
                    if (!iconUrl) {
                        const href = e.getAttribute('href');
                        if (href) iconUrl = href;
                    }
                }
            });

        await rewriter.transform(response).text();

        let finalUrl;
        if (iconUrl) {
            finalUrl = new URL(iconUrl, targetUrl).toString();
        } else {
            finalUrl = new URL('/favicon.ico', targetUrl).toString();
        }

        const iconResponse = await fetch(finalUrl, { 
            headers: headers 
        });

        if (iconResponse.ok && iconResponse.headers.get('content-type')?.includes('image')) {
            return iconResponse;
        }
        
        throw new Error('Icon fetch failed');
    } catch (e) {}
    return null;
}

async function handleIconProxy(request, waitUntil) {
    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');

    if (!targetUrl) return new Response('Missing URL', { status: 400 });

    const cacheKey = new Request(url.toString(), request);
    const cache = caches.default;
    
    let response = await cache.match(cacheKey);

    if (response) {
        response = new Response(response.body, response);
        response.headers.set('X-Icon-Cache-Status', 'HIT');
    } else {
        let upstreamResponse = null;
        if (USE_DEFAULT_IMGAPI) {
            const upstreamApi = `${DEFAULT_IMGAPI}${encodeURIComponent(targetUrl)}`;
            upstreamResponse = await fetch(upstreamApi, {
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }
            });
        } else {
            upstreamResponse = await fetchBestIcon(targetUrl);
        }
        if (upstreamResponse) {
            response = new Response(upstreamResponse.body, upstreamResponse);
            response.headers.set('Cache-Control', 'public, max-age=604800, s-maxage=604800');
            response.headers.set('Access-Control-Allow-Origin', '*');
            response.headers.set('X-Icon-Cache-Status', 'MISS');
            if (waitUntil) waitUntil(cache.put(cacheKey, response.clone()));
        } else {
            const defaultSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 64 64"><path fill="#000000" d="M62 32C62 15.432 48.568 2 32 2C15.861 2 2.703 14.746 2.031 30.72c-.008.196-.01.395-.014.592c-.005.23-.017.458-.017.688v.101C2 48.614 15.432 62 32 62s30-13.386 30-29.899l-.002-.049z"/></svg>`;
            
            response = new Response(defaultSVG, {
                status: 200,
                headers: {
                    'Content-Type': 'image/svg+xml',
                    'Cache-Control': 'public, max-age=3600' 
                }
            });
            response.headers.set('X-Icon-Cache-Status', 'DEFAULT');
        }
        response.headers.set('Access-Control-Allow-Origin', '*');
    }

    return response;
}

const MIN_BACKUP_INTERVAL_MS = 10 * 60 * 1000; 

async function handleSmartBackup(env, currentData) {
    try {
        const list = await env.CARD_ORDER.list({ prefix: `backup_${DEFAULT_USER}_` });
        let keys = list.keys;
        
        keys.sort((a, b) => a.name.localeCompare(b.name));
        
        let shouldBackup = true;

        if (keys.length > 0) {
            const lastBackupMeta = keys[keys.length - 1].metadata;
            if (lastBackupMeta && lastBackupMeta.timestamp) {
                 const timeDiff = Date.now() - lastBackupMeta.timestamp;
                 if (timeDiff < MIN_BACKUP_INTERVAL_MS) {
                     shouldBackup = false; 
                 }
            }
        }

        if (shouldBackup) {
            const now = Date.now();
            const date = new Date(now + 8 * 3600 * 1000);
            const dateStr = date.toISOString().replace(/[:.]/g, '-');
            const backupKey = `backup_${DEFAULT_USER}_${dateStr}`;
            
            await env.CARD_ORDER.put(backupKey, currentData, {
                metadata: { timestamp: now }
            });

            if (keys.length >= 10) { 
                const deleteCount = keys.length + 1 - 10;
                if(deleteCount > 0) {
                    const toDelete = keys.slice(0, deleteCount);
                    for (const key of toDelete) {
                        await env.CARD_ORDER.delete(key.name);
                    }
                }
            }
        }
    } catch (e) {
        console.error("Smart backup failed:", e);
    }
}

export async function onRequest(context) {
    const { request, env, waitUntil } = context;
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === '/api/icon') {
        return handleIconProxy(request, waitUntil);
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
        const RATE_LIMIT_PREFIX = '__limit__';
        const MAX_ATTEMPTS = 5;
        const LOCK_MS = 900 * 1000;
        try {
            const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
            const rateLimitKey = `${RATE_LIMIT_PREFIX}login_${clientIP}`;
            const kv = await env.CARD_ORDER.getWithMetadata(rateLimitKey, { type: 'text' });
            const attempts = parseInt(kv.value) || 0;
            const expiredAt = (kv.metadata && kv.metadata.expiredAt) || 0;

            if (attempts >= MAX_ATTEMPTS) {
                const waitSec = Math.max(1, Math.ceil((expiredAt - Date.now()) / 1000));
                return new Response(JSON.stringify({ valid: false, locked: true, remaining: 0, retryAfter: waitSec }), { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }

            const { password } = await request.json();
            if (password !== env.ADMIN_PASSWORD) {
                const newAttempts = attempts + 1;
                const newExpiredAt = Date.now() + LOCK_MS;
                await env.CARD_ORDER.put(rateLimitKey, String(newAttempts), { expirationTtl: 900, metadata: { expiredAt: newExpiredAt } });
                const remaining = Math.max(0, MAX_ATTEMPTS - newAttempts);
                if (newAttempts >= MAX_ATTEMPTS) {
                    return new Response(JSON.stringify({ valid: false, locked: true, remaining: 0, retryAfter: Math.max(1, Math.ceil((newExpiredAt - Date.now()) / 1000)) }), { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
                }
                return new Response(JSON.stringify({ valid: false, remaining }), { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            await env.CARD_ORDER.delete(rateLimitKey);

            const currentTime = Math.floor(Date.now() / 1000);

            const accessTokenPayload = { 
                iat: currentTime, 
                exp: currentTime + 7200, 
                role: 'admin',
                type: 'access' 
            };
            const accessToken = await createJWT(accessTokenPayload, env.JWT_SECRET);
            
            const refreshTokenPayload = { 
                iat: currentTime, 
                exp: currentTime + 2592000, 
                role: 'admin',
                type: 'refresh' 
            };
            const refreshToken = await createJWT(refreshTokenPayload, env.JWT_SECRET);
            
            const response = new Response(JSON.stringify({ 
                valid: true, 
                token: `Bearer ${accessToken}` 
            }), { 
                status: 200, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            });
            
            response.headers.append('Set-Cookie', `refreshToken=${refreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/api/refreshToken; Max-Age=2592000`);
            return response;
        } catch (e) {
            return new Response(JSON.stringify({ valid: false, error: 'Auth failed' }), { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
        }
    }

    if (url.pathname === '/api/refreshToken' && request.method === 'POST') {
        try {
            const cookies = parseCookie(request.headers.get('Cookie'));
            const refreshToken = cookies.refreshToken;
            
            if (!refreshToken) {
                return new Response(JSON.stringify({ error: 'Refresh token missing' }), { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            
            const payload = await validateJWT(refreshToken, env.JWT_SECRET);
            const currentTime = Math.floor(Date.now() / 1000);

            if (!payload || payload.exp < currentTime) {
                return new Response(JSON.stringify({ error: 'Refresh token expired' }), { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            
            if (payload.type !== 'refresh') {
                return new Response(JSON.stringify({ error: 'Invalid token type' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            
            const newAccessTokenPayload = { 
                iat: currentTime, 
                exp: currentTime + 7200, 
                role: 'admin',
                type: 'access' 
            };
            const newAccessToken = await createJWT(newAccessTokenPayload, env.JWT_SECRET);

            const newRefreshTokenPayload = {
                iat: currentTime,
                exp: currentTime + 2592000,
                role: 'admin',
                type: 'refresh'
            };
            const newRefreshToken = await createJWT(newRefreshTokenPayload, env.JWT_SECRET);
            
            const response = new Response(JSON.stringify({ 
                accessToken: `Bearer ${newAccessToken}` 
            }), { 
                status: 200, 
                headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
            });

            response.headers.append('Set-Cookie', `refreshToken=${newRefreshToken}; HttpOnly; Secure; SameSite=Strict; Path=/api/refreshToken; Max-Age=2592000`);
            return response;
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
        }
    }

    if (url.pathname === '/api/validateToken') {
        const validation = await validateServerToken(request.headers.get('Authorization'), env);
        return new Response(JSON.stringify(validation.isValid ? { valid: true } : validation.response), {
            status: validation.status || 200, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }

    if (url.pathname === '/api/getLinks') {
        const authToken = request.headers.get('Authorization');
        const dataStr = await env.CARD_ORDER.get(DEFAULT_USER);

        if (dataStr) {
            const parsedData = JSON.parse(dataStr);
            const normalizedCategories = normalizeCategories(parsedData.categories || {});
            let isAuthorized = false;

            if (authToken) {
                const validation = await validateServerToken(authToken, env);
                if (validation.isValid) {
                    isAuthorized = true;
                }
            }

            if (isAuthorized) {
                return new Response(JSON.stringify(parsedData), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
            }

            const filteredCategories = {};
            for (const cat in normalizedCategories) {
                const catData = normalizedCategories[cat];
                if (!catData.isHidden) {
                    const publicLinks = (catData.links || []).filter(l => !l.isPrivate);
                    if (publicLinks.length > 0) {
                        filteredCategories[cat] = { ...catData, links: publicLinks };
                    }
                }
            }
            return new Response(JSON.stringify({ categories: filteredCategories }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
        }
        return new Response(JSON.stringify({ categories: {} }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
    }

    if (url.pathname === '/api/saveData' && request.method === 'POST') {
        const validation = await validateServerToken(request.headers.get('Authorization'), env);
        if (!validation.isValid) return new Response(JSON.stringify(validation.response), { status: validation.status, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });

        try {
            const { categories } = await request.json();
            const currentData = await env.CARD_ORDER.get(DEFAULT_USER);
            
            if (currentData) {
                if (waitUntil) waitUntil(handleSmartBackup(env, currentData));
            }

            await env.CARD_ORDER.put(DEFAULT_USER, JSON.stringify({ categories }));
            return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Bad Request' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
        }
    }

    if (url.pathname === '/api/backupData' && request.method === 'POST') {
        const validation = await validateServerToken(request.headers.get('Authorization'), env);
        if (!validation.isValid) return new Response(JSON.stringify(validation.response), { status: validation.status, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
        
        const sourceData = await env.CARD_ORDER.get(DEFAULT_USER);
        if(sourceData) {
             const now = Date.now();
             const date = new Date(now + 8 * 3600 * 1000);
             const dateStr = date.toISOString().replace(/[:.]/g, '-');
             await env.CARD_ORDER.put(`backup_${DEFAULT_USER}_${dateStr}`, sourceData, {
                 metadata: { timestamp: now }
             });
             return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
        }
        return new Response(JSON.stringify({ success: false, error: 'User data not found' }), { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
    }
    
    if (url.pathname === '/api/exportData' && request.method === 'POST') {
         const validation = await validateServerToken(request.headers.get('Authorization'), env);
         if (!validation.isValid) return new Response(JSON.stringify(validation.response), { status: validation.status, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
         
         const data = await env.CARD_ORDER.get(DEFAULT_USER);
         return new Response(data || '{}', { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
    }
    
    if (url.pathname === '/api/importData' && request.method === 'POST') {
         const validation = await validateServerToken(request.headers.get('Authorization'), env);
         if (!validation.isValid) return new Response(JSON.stringify(validation.response), { status: validation.status, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
          
         const body = await request.json();
         const cleanData = { categories: body.categories || {} };
         
         await env.CARD_ORDER.put(DEFAULT_USER, JSON.stringify(cleanData));
         return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json'} });
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders });
}

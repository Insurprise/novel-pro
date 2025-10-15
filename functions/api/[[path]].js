/* =================================================================
 *  Cloudflare Worker Backend (FINAL VERSION 3.0)
 *  功能: 章节收藏、进度保存、用户认证。
 *  升级: 替换片段收藏为章节收藏，并提供拉取收藏列表的 API。
 * ================================================================= */

// --- 1. 配置 ---
const allowedOrigins = [ "https://novel-pro.20100505.xyz", "https://santi.20100505.xyz" ];

// --- 2. 辅助函数 ---
function handleOptions(request) { const origin = request.headers.get("Origin"); if (isOriginAllowed(origin, request)) { return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400" } }); } return new Response("Forbidden", { status: 403 }); }
function jsonResponse(data, status = 200, request) { const origin = request.headers.get("Origin"); const headers = { "Content-Type": "application/json;charset=UTF-8" }; if (isOriginAllowed(origin, request)) { headers["Access-Control-Allow-Origin"] = origin; } return new Response(JSON.stringify(data, null, 2), { status, headers }); }
const hashPassword = async(password)=>{const d=new TextEncoder().encode(password+"a-very-strong-and-secret-salt"),h=await crypto.subtle.digest('SHA-256',d);return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')};
const getUserFromToken = (req) => { const h = req.headers.get('Authorization'); if (!h || !h.startsWith('Bearer ')) return null; try { return JSON.parse(atob(h.substring(7))); } catch (e) { return null; } };
function isOriginAllowed(origin, request) {
    if (!origin) return true; // Allow server-side rendering or same-origin requests
    const hostname = new URL(request.url).hostname;
    //如果请求是来自主域名或者子域名，都允许
    if (origin.endsWith('.20100505.xyz') || hostname.endsWith('.20100505.xyz')) {
        if (!allowedOrigins.includes(origin)) {
            allowedOrigins.push(origin);
        }
        return true;
    }
    return allowedOrigins.includes(origin);
}

// --- 3. API 主入口 ---
export async function onRequest(context) {
    const { request } = context;
    if (request.method === "OPTIONS") return handleOptions(request);
    return handleApiRequest(context);
}

// --- 4. 核心API路由逻辑 ---
async function handleApiRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const pathParts = context.params.path || [];
    const user = getUserFromToken(request);

    try {
        if (pathParts[0] === 'register'||pathParts[0] === 'login') { /* ... 注册登录逻辑未变 ... */ const { username, password } = await request.json(); if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request); const password_hash = await hashPassword(password); if(pathParts[0] === 'register'){ const existing = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first(); if (existing) return jsonResponse({ error: '用户名已存在' }, 409, request); const count = await env.DB.prepare("SELECT COUNT(id) as c FROM Users").first('c'); await env.DB.prepare("INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)").bind(username, password_hash, (count===0?'admin':'user')).run(); return jsonResponse({ message: '用户注册成功' }, 201, request); } if(pathParts[0] === 'login'){ const userDb = await env.DB.prepare("SELECT id, username, role FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first(); if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request); const userData = { userId: userDb.id, username: userDb.username, role: userDb.role }; const token = btoa(JSON.stringify(userData)); return jsonResponse({ token, user: userData }, 200, request); } }

        if (!user) return jsonResponse({ error: '未授权或Token无效' }, 401, request);

        // ★★★ 全新的章节收藏API (FavoriteChapters) ★★★
        if (pathParts[0] === 'favorites') {
            const userId = user.userId;
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare(
                    "SELECT id, novel_id, chapter_id, chapter_index, chapter_title, created_at FROM FavoriteChapters WHERE user_id = ? ORDER BY novel_id, chapter_index"
                ).bind(userId).all();
                return jsonResponse(results, 200, request);
            }
            if (request.method === 'POST') {
                const { novel_id, chapter_id, chapter_index, chapter_title } = await request.json();
                if (!novel_id || !chapter_id || chapter_index == null || !chapter_title) {
                    return jsonResponse({ error: '缺少必要收藏信息' }, 400, request);
                }
                const { meta } = await env.DB.prepare(
                    "INSERT OR IGNORE INTO FavoriteChapters (user_id, novel_id, chapter_id, chapter_index, chapter_title) VALUES (?, ?, ?, ?, ?)"
                ).bind(userId, novel_id, chapter_id, chapter_index, chapter_title).run();
                return jsonResponse({ message: '章节收藏成功', created: meta.changes > 0 }, 201, request);
            }
            if (request.method === 'DELETE') {
                const { novel_id, chapter_id } = await request.json();
                 if (!novel_id || !chapter_id) {
                    return jsonResponse({ error: '缺少必要删除信息' }, 400, request);
                }
                await env.DB.prepare(
                    "DELETE FROM FavoriteChapters WHERE user_id = ? AND novel_id = ? AND chapter_id = ?"
                ).bind(userId, novel_id, chapter_id).run();
                return jsonResponse(null, 204, request);
            }
        }

        // --- 用户阅读进度 (无变化) ---
        if (pathParts[0] === 'progress' && pathParts[1]) { const novel_id = pathParts[1]; if (request.method === 'POST') { const { chapter_id, position } = await request.json(); await env.DB.prepare(`INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id=?3, position=?4, updated_at=CURRENT_TIMESTAMP`).bind(user.userId, novel_id, chapter_id, position).run(); return jsonResponse({ message: '进度已保存' }, 200, request); } if (request.method === 'GET') { const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id=? AND novel_id=?").bind(user.userId, novel_id).first(); if (!record) return jsonResponse({}, 404, request); return jsonResponse(record, 200, request); } }

        return jsonResponse({ error: `API路由未找到: /${pathParts.join('/')}` }, 404, request);

    } catch (e) { console.error("API请求处理时发生未捕获的严重错误:", e.message, e.stack); return jsonResponse({ error: '服务器内部发生未知错误', details: e.message }, 500, request); }
}

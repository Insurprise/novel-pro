/* =================================================================
 *  Cloudflare Worker Backend (FINAL FEATURE-COMPLETE VERSION)
 *  功能更新:
 *  1. [新增] 书摘功能 (/api/snippets): 实现获取、保存、删除书摘。
 *  2. [修改] 小说列表 (/api/novels): 允许普通登录用户获取小说列表。
 * ================================================================= */

// --- 1. 配置 ---
const allowedOrigins = [
    "https://novel-pro.20100505.xyz",
    "https://santi.20100505.xyz",
];

// --- 2. 辅助函数 ---
function handleOptions(request) { /* ... */ }
function jsonResponse(data, status = 200, request) { /* ... */ }
function corsHeaders(request) { /* ... */ }
const hashPassword = async (password) => { /* ... */ };
const getUserFromToken = (req) => { /* ... */ };

// --- 3. API 主入口 ---
export async function onRequest(context) {
    const { request } = context;
    if (request.method === "OPTIONS") {
        return handleOptions(request);
    }
    return await handleApiRequest(context);
}

// --- 4. 核心API路由逻辑 ---
async function handleApiRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const pathParts = context.params.path || [];
    const user = getUserFromToken(request);

    try {
        // --- 公共路由 ---
        if (pathParts[0] === 'register' && request.method === 'POST') { /* ... */ }
        if (pathParts[0] === 'login' && request.method === 'POST') { /* ... */ }

        // --- 需要登录 ---
        if (!user) return jsonResponse({ error: '未授权访问' }, 401, request);
        
        // --- 导航链接管理 ---
        if (pathParts[0] === 'navlinks') { /* ... */ }
        
        // --- 小说管理 ---
        if (pathParts[0] === 'novels') {
            // ★★★ 关键修改 ★★★
            // GET /api/novels 现在对所有登录用户开放
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare("SELECT id, title, author FROM Novels ORDER BY id").all();
                return jsonResponse(results, 200, request);
            }
            // 其他操作仍然需要管理员权限
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            
            if (request.method === 'POST') { /* ... */ }
            if (request.method === 'PUT' && pathParts[1]) { /* ... */ }
            if (request.method === 'DELETE' && pathParts[1]) { /* ... */ }
        }

        // ★★★ 本次新增的功能 ★★★
        // --- 书摘管理 (Snippets) ---
        if (pathParts[0] === 'snippets') {
            // GET /api/snippets?novel_id=xxx&chapter_id=yyy (获取书摘)
            if (request.method === 'GET') {
                const novel_id = url.searchParams.get('novel_id');
                const chapter_id = url.searchParams.get('chapter_id');
                if (!novel_id || !chapter_id) {
                    return jsonResponse({ error: "novel_id 和 chapter_id 是必须的" }, 400, request);
                }
                const { results } = await env.DB.prepare(
                    "SELECT id, content, created_at FROM Snippets WHERE user_id = ? AND novel_id = ? AND chapter_id = ? ORDER BY created_at DESC"
                ).bind(user.userId, novel_id, chapter_id).all();
                return jsonResponse(results, 200, request);
            }
            // POST /api/snippets (保存新书摘)
            if (request.method === 'POST') {
                const { novel_id, chapter_id, content } = await request.json();
                if (!novel_id || !chapter_id || !content) {
                    return jsonResponse({ error: "缺少必要字段" }, 400, request);
                }
                const { meta } = await env.DB.prepare(
                    "INSERT INTO Snippets (user_id, novel_id, chapter_id, content) VALUES (?, ?, ?, ?)"
                ).bind(user.userId, novel_id, chapter_id, content).run();
                return jsonResponse({ id: meta.last_row_id, message: '书摘已保存' }, 201, request);
            }
            // DELETE /api/snippets/:id (删除书摘)
            if (request.method === 'DELETE' && pathParts[1]) {
                const snippetId = pathParts[1];
                await env.DB.prepare("DELETE FROM Snippets WHERE id = ? AND user_id = ?")
                    .bind(snippetId, user.userId).run();
                return new Response(null, { status: 204, headers: corsHeaders(request) });
            }
        }
        // ★★★ 新增结束 ★★★

        // --- 用户阅读进度 ---
        if (pathParts[0] === 'progress' && pathParts[1]) { /* ... */ }

        // 未匹配路由
        return jsonResponse({ error: `API 路由未找到: /api/${pathParts.join('/')}` }, 404, request);

    } catch (e) {
        console.error(e.message, e.stack);
        return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request);
    }
}


/* =================================================================
 * 完整的、未省略的函数代码 (请用这部分完整替换)
 * ================================================================= */

function handleOptions(request) {const origin = request.headers.get("Origin");if (allowedOrigins.includes(origin)) {return new Response(null, {status: 204,headers: {"Access-Control-Allow-Origin": origin,"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS","Access-Control-Allow-Headers": "Content-Type, Authorization","Access-Control-Max-Age": "86400",},});} else {return new Response("Forbidden", { status: 403 });}}
function jsonResponse(data, status = 200, request) {const origin = request.headers.get("Origin");const headers = { "Content-Type": "application/json;charset=UTF-8" };if (allowedOrigins.includes(origin)) {headers["Access-Control-Allow-Origin"] = origin;}return new Response(JSON.stringify(data, null, 2), { status, headers });}
function corsHeaders(request) {const origin = request.headers.get("Origin");const headers = {};if (allowedOrigins.includes(origin)) {headers["Access-Control-Allow-Origin"] = origin;}return headers;}
const hashPassword = async (password) => {const encoder = new TextEncoder();const data = encoder.encode(password + "a-very-strong-and-secret-salt");const hashBuffer = await crypto.subtle.digest('SHA-256', data);const hashArray = Array.from(new Uint8Array(hashBuffer));return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');};
const getUserFromToken = (req) => {const authHeader = req.headers.get('Authorization');if (!authHeader || !authHeader.startsWith('Bearer ')) return null;const token = authHeader.substring(7);try { return JSON.parse(atob(token)); } catch (e) { return null; }};

async function handleApiRequest(context) {const { request, env } = context;const url = new URL(request.url);const pathParts = context.params.path || [];const user = getUserFromToken(request);try {if (pathParts[0] === 'register' && request.method === 'POST') {const { username, password } = await request.json();if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request);const existingUser = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first();if (existingUser) return jsonResponse({ error: '用户名已存在' }, 409, request);const password_hash = await hashPassword(password);const userCountResult = await env.DB.prepare("SELECT COUNT(id) as count FROM Users").first();const role = (!userCountResult || userCountResult.count === 0) ? 'admin' : 'user';await env.DB.prepare("INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)") .bind(username, password_hash, role).run();return jsonResponse({ message: '用户注册成功' }, 201, request);}if (pathParts[0] === 'login' && request.method === 'POST') {const { username, password } = await request.json();const password_hash = await hashPassword(password);const userDb = await env.DB.prepare("SELECT id, username, role FROM Users WHERE username = ? AND password_hash = ?") .bind(username, password_hash).first();if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request);const userData = { userId: userDb.id, username: userDb.username, role: userDb.role, timestamp: Date.now() };const sessionToken = btoa(JSON.stringify(userData));return jsonResponse({ token: sessionToken, user: userData }, 200, request);}if (!user) return jsonResponse({ error: '未授权访问' }, 401, request);if (pathParts[0] === 'navlinks') {if (request.method === 'GET') {const { results } = await env.DB.prepare("SELECT id, name, subdomain FROM NavLinks ORDER BY name").all();return jsonResponse(results, 200, request);}if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);if (request.method === 'POST') {const { name, subdomain } = await request.json();const { meta } = await env.DB.prepare("INSERT INTO NavLinks (name, subdomain) VALUES (?, ?)") .bind(name, subdomain).run();return jsonResponse({ id: meta.last_row_id, name, subdomain }, 201, request);}if (request.method === 'PUT' && pathParts[1]) {const { name, subdomain } = await request.json();await env.DB.prepare("UPDATE NavLinks SET name = ?, subdomain = ? WHERE id = ?") .bind(name, subdomain, pathParts[1]).run();return jsonResponse({ message: '更新成功' }, 200, request);}if (request.method === 'DELETE' && pathParts[1]) {await env.DB.prepare("DELETE FROM NavLinks WHERE id = ?").bind(pathParts[1]).run();return new Response(null, { status: 204, headers: corsHeaders(request) });}}if (pathParts[0] === 'novels') {if (request.method === 'GET') {const { results } = await env.DB.prepare("SELECT id, title, author FROM Novels ORDER BY id").all();return jsonResponse(results, 200, request);}if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);if (request.method === 'POST') {const { id, title, author } = await request.json();if (!id || !title) return jsonResponse({ error: 'ID和标题不能为空' }, 400, request);await env.DB.prepare("INSERT INTO Novels (id, title, author) VALUES (?, ?, ?)") .bind(id, title, author).run();return jsonResponse({ id, title, author }, 201, request);}if (request.method === 'PUT' && pathParts[1]) {const novelId = pathParts[1];const { title, author } = await request.json();if (!title) return jsonResponse({ error: '标题不能为空' }, 400, request);await env.DB.prepare("UPDATE Novels SET title = ?, author = ? WHERE id = ?") .bind(title, author, novelId).run();return jsonResponse({ id: novelId, title, author }, 200, request);}if (request.method === 'DELETE' && pathParts[1]) {await env.DB.prepare("DELETE FROM Novels WHERE id = ?").bind(pathParts[1]).run();return new Response(null, { status: 204, headers: corsHeaders(request) });}}if (pathParts[0] === 'snippets') {if (request.method === 'GET') {const novel_id = url.searchParams.get('novel_id');const chapter_id = url.searchParams.get('chapter_id');if (!novel_id || !chapter_id) {return jsonResponse({ error: "novel_id 和 chapter_id 是必须的" }, 400, request);}const { results } = await env.DB.prepare( "SELECT id, content, created_at FROM Snippets WHERE user_id = ? AND novel_id = ? AND chapter_id = ? ORDER BY created_at DESC" ).bind(user.userId, novel_id, chapter_id).all();return jsonResponse(results, 200, request);}if (request.method === 'POST') {const { novel_id, chapter_id, content } = await request.json();if (!novel_id || !chapter_id || !content) {return jsonResponse({ error: "缺少必要字段" }, 400, request);}const { meta } = await env.DB.prepare( "INSERT INTO Snippets (user_id, novel_id, chapter_id, content) VALUES (?, ?, ?, ?)" ).bind(user.userId, novel_id, chapter_id, content).run();return jsonResponse({ id: meta.last_row_id, message: '书摘已保存' }, 201, request);}if (request.method === 'DELETE' && pathParts[1]) {const snippetId = pathParts[1];await env.DB.prepare("DELETE FROM Snippets WHERE id = ? AND user_id = ?") .bind(snippetId, user.userId).run();return new Response(null, { status: 204, headers: corsHeaders(request) });}}if (pathParts[0] === 'progress' && pathParts[1]) {const novel_id = pathParts[1];if (request.method === 'POST') {const { chapter_id, position } = await request.json();await env.DB.prepare(` INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id = ?3, position = ?4, updated_at = CURRENT_TIMESTAMP `).bind(user.userId, novel_id, chapter_id, position).run();return jsonResponse({ message: '进度已保存' }, 200, request);}if (request.method === 'GET') {const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id = ? AND novel_id = ?") .bind(user.userId, novel_id).first();if (!record) return jsonResponse({ error: "No record found" }, 404, request);return jsonResponse(record, 200, request);}}return jsonResponse({ error: `API 路由未找到: /api/${pathParts.join('/')}` }, 404, request);} catch (e) {console.error(e.message, e.stack);return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request);}}

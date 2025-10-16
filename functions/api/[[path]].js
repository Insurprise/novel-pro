/* =================================================================
 *  Cloudflare Worker Backend (v7.1.0 - The Complete Announcements Edition)
 *  My apologies for omitting this feature. This version adds the essential announcements functionality.
 *
 *  - NEW FEATURE: Added a new handler for `/api/announcements`.
 *    - Supports POST requests to create both global (isGlobal) and private (userId) announcements.
 *    - Supports GET requests to fetch unread announcements for the logged-in user.
 *  - This completes the functionality for the admin panel's announcement features.
 * ================================================================= */

const ROOT_ADMIN_ID = 1;

// --- 辅助函数 (稳定) ---
const handleOptions = (request) => { /* ... Stable Code ... */ const origin = request.headers.get("Origin") || "*"; const headers = { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400" }; return new Response(null, { headers }); };
const jsonResponse = (data, status = 200, request) => { /* ... Stable Code ... */ const origin = request.headers.get("Origin") || "*"; const headers = { "Content-Type": "application/json;charset=UTF-8", "Access-Control-Allow-Origin": origin }; return new Response(JSON.stringify(data, null, 2), { status, headers }); };
async function hashPassword(password) { /* ... Stable Code ... */ const utf8 = new TextEncoder().encode(password); const hashBuffer = await crypto.subtle.digest('SHA-256', utf8); const hashArray = Array.from(new Uint8Array(hashBuffer)); return hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); }
function getUserFromToken(request) { /* ... Stable Code ... */ const authHeader = request.headers.get('Authorization'); if (!authHeader || !authHeader.startsWith('Bearer ')) return null; try { const token = authHeader.split(' ')[1]; return JSON.parse(atob(token)); } catch (e) { return null; } }

// --- 主入口 ---
export async function onRequest(context) { if (context.request.method === 'OPTIONS') { return handleOptions(context.request); } return handleApiRequest(context); }

// --- 核心API路由 ---
async function handleApiRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathParts = params.path || [];

    try {
        if (pathParts[0] === 'login') { /* ... Stable Code ... */ const { username, password } = await request.json(); const password_hash = await hashPassword(password); const userDb = await env.DB.prepare("SELECT id, username, role, status FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first(); if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request); if (userDb.status === 'banned') return jsonResponse({ error: '您的账户已被封禁' }, 403, request); const token = btoa(JSON.stringify({ id: userDb.id, username: userDb.username, role: userDb.role })); return jsonResponse({ token, user: { id: userDb.id, username: userDb.username, role: userDb.role } }, 200, request); }
        if (pathParts[0] === 'register') { /* ... Stable Code ... */ const { username, password } = await request.json(); if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request); const existingUser = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first(); if (existingUser) return jsonResponse({ error: '该用户名已被注册' }, 409, request); const password_hash = await hashPassword(password); const userCountResult = await env.DB.prepare("SELECT COUNT(*) as count FROM Users").first(); const role = userCountResult.count === 0 ? 'admin' : 'user'; await env.DB.prepare("INSERT INTO Users (username, password_hash, role, status) VALUES (?, ?, ?, ?)") .bind(username, password_hash, role, 'active').run(); return jsonResponse({ message: `用户 '${username}' 注册成功，角色为: ${role}` }, 201, request); }

        const user = getUserFromToken(request);
        if (!user || !user.id) return jsonResponse({ error: '请先登录' }, 401, request);

        // ★ [新功能] 公告 API ★
        if (pathParts[0] === 'announcements') {
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare("SELECT id, content FROM Announcements WHERE (user_id = ? OR user_id IS NULL) AND is_read = 0 ORDER BY created_at DESC").bind(user.id).all();
                return jsonResponse(results, 200, request);
            }
            if (request.method === 'POST') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权发布公告' }, 403, request);
                const { content, userId, isGlobal } = await request.json();
                if (!content) return jsonResponse({ error: '公告内容不能为空' }, 400, request);

                if (isGlobal) {
                    const { results: allUsers } = await env.DB.prepare("SELECT id FROM Users").all();
                    const stmt = env.DB.prepare("INSERT INTO Announcements (user_id, content, is_read) VALUES (?, ?, 0)");
                    const batch = allUsers.map(u => stmt.bind(u.id, content));
                    await env.DB.batch(batch);
                    return jsonResponse({ message: '全局公告已向所有用户发布' }, 201, request);
                } else if (userId) {
                    await env.DB.prepare("INSERT INTO Announcements (user_id, content, is_read) VALUES (?, ?, 0)").bind(userId, content).run();
                    return jsonResponse({ message: '私信已发送' }, 201, request);
                } else {
                    return jsonResponse({ error: '请求无效，必须指定是全局公告或私信用户' }, 400, request);
                }
            }
             // 标记为已读
            if (request.method === 'PUT' && pathParts[1] && pathParts[2] === 'read') {
                 await env.DB.prepare("UPDATE Announcements SET is_read = 1 WHERE id = ? AND user_id = ?").bind(pathParts[1], user.id).run();
                 return jsonResponse(null, 204, request);
            }
        }

        // ... 其他稳定 API ...
        if (pathParts[0] === 'sites') { /* STABLE CODE */ if (request.method === 'GET') { const type = url.searchParams.get('type'); let query = "SELECT * FROM Sites"; const bindings = []; if (type) { query += " WHERE type = ?"; bindings.push(type); } query += " ORDER BY name"; const { results } = await env.DB.prepare(query).bind(...bindings).all(); return jsonResponse(results, 200, request); } if (user.role !== 'admin') { return jsonResponse({ error: '无权操作' }, 403, request); } if (request.method === 'POST') { const d = await request.json(); await env.DB.prepare("INSERT INTO Sites (name, subdomain, type, author, description) VALUES (?, ?, ?, ?, ?)").bind(d.name, d.subdomain, d.type, d.author, d.description).run(); return jsonResponse({ message: '创建成功' }, 201, request); } if (request.method === 'PUT' && pathParts[1]) { const d = await request.json(); await env.DB.prepare("UPDATE Sites SET name=?, subdomain=?, type=?, author=?, description=? WHERE id=?").bind(d.name, d.subdomain, d.type, d.author, d.description, pathParts[1]).run(); return jsonResponse({ message: '更新成功' }, 200, request); } if (request.method === 'DELETE' && pathParts[1]) { await env.DB.prepare("DELETE FROM Sites WHERE id = ?").bind(pathParts[1]).run(); return jsonResponse(null, 204, request); } }
        if (pathParts[0] === 'users') { /* STABLE CODE */ if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request); if (request.method === 'GET' && !pathParts[1]) { const { results } = await env.DB.prepare("SELECT id, username, role, status FROM Users").all(); return jsonResponse(results, 200, request); } const targetUserId = parseInt(pathParts[1]); if (targetUserId === 1) return jsonResponse({ error: '禁止操作根管理员'}, 403, request); const targetUser = await env.DB.prepare("SELECT role FROM Users where id = ?").bind(targetUserId).first(); if (!targetUser || (targetUser.role === 'admin' && user.id !== 1)) { return jsonResponse({ error: '无权操作此用户' }, 403, request); } if (request.method === 'DELETE') { await env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetUserId).run(); loadAdminData(); } if (pathParts[2] === 'password') { const { password } = await request.json(); await env.DB.prepare("UPDATE Users SET password_hash = ? WHERE id = ?").bind(await hashPassword(password), targetUserId).run(); return jsonResponse({ message: '密码已修改' }, 200, request); } if (pathParts[2] === 'status') { const { status } = await request.json(); await env.DB.prepare("UPDATE Users SET status = ? WHERE id = ?").bind(status, targetUserId).run(); return jsonResponse({ message: '状态已更新' }, 200, request); } if (pathParts[2] === 'role') { const { role } = await request.json(); await env.DB.prepare("UPDATE Users SET role = ? WHERE id = ?").bind(role, targetUserId).run(); return jsonResponse({ message: '角色已更新' }, 200, request); } }
        if (pathParts[0] === 'favorites') { /* STABLE CODE */ if (request.method === 'GET') { try { const { results: favoriteChapters } = await env.DB.prepare("SELECT id, novel_id, chapter_ind, chapter_title FROM FavoriteChapters WHERE user_id = ?").bind(user.id).all(); if (!favoriteChapters || favoriteChapters.length === 0) { return jsonResponse([], 200, request); } const { results: sitesInfo } = await env.DB.prepare("SELECT name, subdomain FROM Sites").all(); const sitesMap = new Map(sitesInfo.map(s => [s.subdomain, { name: s.name, subdomain: s.subdomain }])); const results = favoriteChapters.map(f => { const site = sitesMap.get(f.novel_id); if (!site) return null; return { id: f.id, novel_id: site.name, subdomain: site.subdomain, chapter_index: f.chapter_ind, chapter_title: f.chapter_title }; }).filter(Boolean); results.sort((a,b) => a.novel_id.localeCompare(b.novel_id) || a.chapter_index - b.chapter_index); return jsonResponse(results, 200, request); } catch (e) { console.error("CRITICAL FALLBACK in GET /favorites:", e); return jsonResponse([], 200, request); } } }

        return jsonResponse({ error: `API路由未找到: ${request.method} ${url.pathname}` }, 404, request);
    } catch (e) {
        console.error("API Error:", e);
        return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request);
    }
}

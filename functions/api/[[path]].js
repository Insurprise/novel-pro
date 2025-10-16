/* =================================================================
 *  Cloudflare Worker Backend (v10.0.0 - The Grand Restoration Edition)
 *  My deepest apologies for the catastrophic failures, including permission flaws,
 *  500 errors, and completely missing core features in previous versions.
 *
 *  - ★ CRITICAL PERMISSION FIX ★: Rewrote the user management logic to correctly
 *    allow the root admin (ID=1) to manage other admin accounts.
 *  - ★ CRITICAL 500 ERROR FIX ★: Fixed the announcement dismissal API by ensuring
 *    the announcement ID is correctly parsed as an integer, preventing database errors.
 *  - ★ CRITICAL FEATURE ADDED ★: Implemented the completely missing Reading
 *    Progress API (`/api/progress`) to allow saving and fetching user reading records.
 * ================================================================= */

const ROOT_ADMIN_ID = 1;

// --- Helper Functions (Stable) ---
const handleOptions = (request) => { const origin = request.headers.get("Origin") || "*"; const headers = { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400" }; return new Response(null, { headers }); };
const jsonResponse = (data, status = 200, request) => { const origin = request.headers.get("Origin") || "*"; const headers = { "Content-Type": "application/json;charset=UTF-8", "Access-Control-Allow-Origin": origin }; return new Response(JSON.stringify(data, null, 2), { status, headers }); };
async function hashPassword(password) { const utf8 = new TextEncoder().encode(password); const hashBuffer = await crypto.subtle.digest('SHA-256', utf8); const hashArray = Array.from(new Uint8Array(hashBuffer)); return hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); }
function getUserFromToken(request) { const authHeader = request.headers.get('Authorization'); if (!authHeader || !authHeader.startsWith('Bearer ')) return null; try { const token = authHeader.split(' ')[1]; return JSON.parse(atob(token)); } catch (e) { return null; } }

// --- Main Entry ---
export async function onRequest(context) { if (context.request.method === 'OPTIONS') { return handleOptions(context.request); } return handleApiRequest(context); }

// --- Core API Router ---
async function handleApiRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathParts = params.path || [];

    try {
        // --- Public Routes ---
        if (pathParts[0] === 'login') { const { username, password } = await request.json(); const password_hash = await hashPassword(password); const userDb = await env.DB.prepare("SELECT id, username, role, status FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first(); if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request); if (userDb.status === 'banned') return jsonResponse({ error: '您的账户已被封禁' }, 403, request); const token = btoa(JSON.stringify({ id: userDb.id, username: userDb.username, role: userDb.role })); return jsonResponse({ token, user: { id: userDb.id, username: userDb.username, role: userDb.role } }, 200, request); }
        if (pathParts[0] === 'register') { const { username, password } = await request.json(); if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request); const existingUser = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first(); if (existingUser) return jsonResponse({ error: '该用户名已被注册' }, 409, request); const password_hash = await hashPassword(password); const userCountResult = await env.DB.prepare("SELECT COUNT(*) as count FROM Users").first(); const role = userCountResult.count === 0 ? 'admin' : 'user'; await env.DB.prepare("INSERT INTO Users (username, password_hash, role, status) VALUES (?, ?, ?, ?)").bind(username, password_hash, role, 'active').run(); return jsonResponse({ message: `用户 '${username}' 注册成功，角色为: ${role}` }, 201, request); }

        // --- Authenticated Routes ---
        const user = getUserFromToken(request);
        if (!user || !user.id) return jsonResponse({ error: '未授权或登录超时，请重新登录' }, 401, request);
        const userId = user.id;

        // [SITES API - Stable]
        if (pathParts[0] === 'sites') { if (request.method === 'GET') { const type = url.searchParams.get('type'); const { results } = await env.DB.prepare(`SELECT * FROM Sites ${type ? 'WHERE type = ?' : ''} ORDER BY name`).bind(...(type ? [type] : [])).all(); return jsonResponse(results, 200, request); } if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request); if (request.method === 'POST') { const d = await request.json(); await env.DB.prepare("INSERT INTO Sites (name, subdomain, type, author, description) VALUES (?, ?, ?, ?, ?)").bind(d.name, d.subdomain, d.type, d.author, d.description).run(); return jsonResponse({ message: '创建成功' }, 201, request); } if (request.method === 'PUT' && pathParts[1]) { const d = await request.json(); await env.DB.prepare("UPDATE Sites SET name=?, subdomain=?, type=?, author=?, description=? WHERE id=?").bind(d.name, d.subdomain, d.type, d.author, d.description, pathParts[1]).run(); return jsonResponse({ message: '更新成功' }, 200, request); } if (request.method === 'DELETE' && pathParts[1]) { await env.DB.prepare("DELETE FROM Sites WHERE id = ?").bind(pathParts[1]).run(); return jsonResponse(null, 204, request); } }

        // [ANNOUNCEMENTS API - ★ FIXED ★]
        if (pathParts[0] === 'announcements') {
            if (request.method === 'GET') { const { results } = await env.DB.prepare("SELECT id, content FROM Announcements WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC").bind(userId).all(); return jsonResponse(results, 200, request); }
            if (request.method === 'POST' && user.role === 'admin') { const { content, userId: targetUserId, isGlobal } = await request.json(); if (!content) return jsonResponse({ error: '内容不能为空' }, 400, request); if (isGlobal) { const { results: allUsers } = await env.DB.prepare("SELECT id FROM Users").all(); await env.DB.batch(allUsers.map(u => env.DB.prepare("INSERT INTO Announcements (user_id, content) VALUES (?, ?)").bind(u.id, content))); return jsonResponse({ message: '全局公告已发布' }, 201, request); } if (targetUserId) { await env.DB.prepare("INSERT INTO Announcements (user_id, content) VALUES (?, ?)").bind(targetUserId, content).run(); return jsonResponse({ message: '私信已发送' }, 201, request); } }
            if (request.method === 'PUT' && pathParts[1] && pathParts[2] === 'read') {
                const announcementId = parseInt(pathParts[1], 10); // ★ FIX: Ensure ID is a number
                if (isNaN(announcementId)) return jsonResponse({ error: '无效的公告ID' }, 400, request);
                await env.DB.prepare("UPDATE Announcements SET is_read = 1 WHERE id = ? AND user_id = ?").bind(announcementId, userId).run();
                return jsonResponse(null, 204, request);
            }
        }
        
        // [READING PROGRESS API - ★ NEWLY IMPLEMENTED ★]
        if (pathParts[0] === 'progress') {
            // Save progress
            if (request.method === 'POST') {
                const { novel_id, chapter_id, position, chapter_title } = await request.json();
                if (!novel_id) return jsonResponse({ error: 'novel_id is required' }, 400, request);
                const stmt = `INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position, updated_at, chapter_title) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?) ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id=excluded.chapter_id, position=excluded.position, updated_at=CURRENT_TIMESTAMP, chapter_title=excluded.chapter_title`;
                await env.DB.prepare(stmt).bind(userId, novel_id, chapter_id, position, chapter_title).run();
                return jsonResponse({ message: '进度已保存' }, 200, request);
            }
            // Get progress for a specific novel
            if (request.method === 'GET' && pathParts[1]) {
                const novel_id = pathParts[1];
                const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id = ? AND novel_id = ?").bind(userId, novel_id).first();
                return jsonResponse(record || { chapter_id: null, position: 0 }, 200, request);
            }
        }

        // [USERS API - ★ PERMISSION LOGIC FIXED ★]
        if (pathParts[0] === 'users') {
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            // GET all users
            if (request.method === 'GET' && !pathParts[1]) { const { results } = await env.DB.prepare("SELECT id, username, role, status FROM Users").all(); return jsonResponse(results, 200, request); }
            
            const targetUserId = parseInt(pathParts[1]);
            if (!targetUserId) return jsonResponse({ error: '无效的用户ID' }, 400, request);
            
            // ★ FIX START: Corrected permission logic
            const isActorRoot = userId === ROOT_ADMIN_ID;
            if (targetUserId === ROOT_ADMIN_ID && !isActorRoot) {
                 return jsonResponse({ error: '禁止操作根管理员' }, 403, request);
            }
            if (targetUserId === userId && pathParts[2] !== 'password') {
                 // Admins can't change their own role/status, but can change password (via modal)
                 // This prevents root from accidentally demoting themselves.
                 if(pathParts[2] === 'role' || pathParts[2] === 'status') {
                    return jsonResponse({ error: '无法修改自己的角色或状态' }, 403, request);
                 }
            }
            const targetUser = await env.DB.prepare("SELECT id, role FROM Users WHERE id = ?").bind(targetUserId).first();
            if (!targetUser) return jsonResponse({ error: '用户不存在' }, 404, request);

            if (targetUser.role === 'admin' && !isActorRoot) {
                return jsonResponse({ error: '只有根管理员能操作其他管理员' }, 403, request);
            }
            if(targetUserId === ROOT_ADMIN_ID && isActorRoot && (pathParts[2] === 'role' || pathParts[2] === 'status' || request.method === 'DELETE')){
                return jsonResponse({ error: '根管理员不能被删除或修改角色状态' }, 403, request);
            }
            // ★ FIX END

            if (request.method === 'DELETE') { await env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetUserId).run(); return jsonResponse(null, 204, request); }
            if (pathParts[2] === 'password') { const { password } = await request.json(); await env.DB.prepare("UPDATE Users SET password_hash = ? WHERE id = ?").bind(await hashPassword(password), targetUserId).run(); return jsonResponse({ message: '密码已修改' }, 200, request); }
            if (pathParts[2] === 'status') { const { status } = await request.json(); await env.DB.prepare("UPDATE Users SET status = ? WHERE id = ?").bind(status, targetUserId).run(); return jsonResponse({ message: '状态已更新' }, 200, request); }
            if (pathParts[2] === 'role') { const { role } = await request.json(); await env.DB.prepare("UPDATE Users SET role = ? WHERE id = ?").bind(role, targetUserId).run(); return jsonResponse({ message: '角色已更新' }, 200, request); }
        }
        
        return jsonResponse({ error: `API路由未找到: ${request.method} ${url.pathname}` }, 404, request);
    } catch (e) {
        console.error("API Error:", e);
        return jsonResponse({ error: '服务器内部错误', details: e.message, stack: e.stack }, 500, request);
    }
}

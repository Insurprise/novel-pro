/* =================================================================
 *  Cloudflare Worker Backend (v3.0 - The Management Platform)
 *  功能: 统一站点管理, 高级用户控制, 公告系统, 动态链接支持
 * ================================================================= */

const ROOT_ADMIN_ID = 1; // 站长ID，永不可被修改

// --- 辅助函数 (基本不变) ---
const handleOptions = (request) => { /* ... */ };
const jsonResponse = (data, status = 200, request) => { const origin = request.headers.get("Origin") || "*"; const headers = { "Content-Type": "application/json;charset=UTF-8", "Access-Control-Allow-Origin": origin }; return new Response(JSON.stringify(data, null, 2), { status, headers }); };
const hashPassword = async(password) => { /* ... */ };
const getUserFromToken = (req) => { /* ... */ };

// --- 主入口 ---
export async function onRequest(context) { /* ... */ }

// --- 核心API路由 ---
async function handleApiRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathParts = params.path || [];
    const user = getUserFromToken(request);

    try {
        // --- 公共路由 ---
        if (pathParts[0] === 'login') {
            const { username, password } = await request.json();
            const password_hash = await hashPassword(password);
            const userDb = await env.DB.prepare("SELECT id, username, role, status FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first();
            if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request);
            if (userDb.status === 'banned') return jsonResponse({ error: '您的账户已被封禁' }, 403, request);
            const token = btoa(JSON.stringify({ id: userDb.id, username: userDb.username, role: userDb.role }));
            return jsonResponse({ token, user: { id: userDb.id, username: userDb.username, role: userDb.role } }, 200, request);
        }
        if (pathParts[0] === 'register') { /* ... */ }

        if (!user) return jsonResponse({ error: '未授权或Token无效' }, 401, request);
        
        // --- ★ 统一站点管理 ★ ---
        if (pathParts[0] === 'sites') {
            if (request.method === 'GET') {
                const type = url.searchParams.get('type');
                let query = "SELECT * FROM Sites";
                const bindings = [];
                if (type) {
                    query += " WHERE type = ?";
                    bindings.push(type);
                }
                query += " ORDER BY name";
                const { results } = await env.DB.prepare(query).bind(...bindings).all();
                return jsonResponse(results, 200, request);
            }
             if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') { const { name, subdomain, type, author, description } = await request.json(); const { meta } = await env.DB.prepare("INSERT INTO Sites (name, subdomain, type, author, description) VALUES (?, ?, ?, ?, ?)").bind(name, subdomain, type, author, description).run(); return jsonResponse({ id: meta.last_row_id, name, subdomain, type }, 201, request); }
            if (request.method === 'PUT' && pathParts[1]) { const { name, subdomain, type, author, description } = await request.json(); await env.DB.prepare("UPDATE Sites SET name=?, subdomain=?, type=?, author=?, description=? WHERE id=?").bind(name, subdomain, type, author, description, pathParts[1]).run(); return jsonResponse({ message: '更新成功' }, 200, request); }
            if (request.method === 'DELETE' && pathParts[1]) { await env.DB.prepare("DELETE FROM Sites WHERE id = ?").bind(pathParts[1]).run(); return jsonResponse(null, 204, request); }
        }

        // --- ★ 高级用户管理 ★ ---
        if (pathParts[0] === 'users') {
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'GET') { const { results } = await env.DB.prepare("SELECT id, username, role, status FROM Users WHERE id != ?").bind(user.id).all(); return jsonResponse(results, 200, request); }
            const targetUserId = parseInt(pathParts[1]);
            const targetUser = await env.DB.prepare("SELECT * FROM Users where id = ?").bind(targetUserId).first();
            if (!targetUser || targetUserId === ROOT_ADMIN_ID || targetUserId === user.id || targetUser.role === 'admin') {
                 return jsonResponse({ error: '无权操作此用户' }, 403, request);
            }
            if (request.method === 'DELETE') { await env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetUserId).run(); return jsonResponse(null, 204, request); }
            if (pathParts[2] === 'password') { const { password } = await request.json(); const hash = await hashPassword(password); await env.DB.prepare("UPDATE Users SET password_hash = ? WHERE id = ?").bind(hash, targetUserId).run(); return jsonResponse({ message: '密码已修改' }, 200, request); }
            if (pathParts[2] === 'status') { const { status } = await request.json(); await env.DB.prepare("UPDATE Users SET status = ? WHERE id = ?").bind(status, targetUserId).run(); return jsonResponse({ message: '状态已更新' }, 200, request); }
            if (pathParts[2] === 'role') { const { role } = await request.json(); await env.DB.prepare("UPDATE Users SET role = ? WHERE id = ?").bind(role, targetUserId).run(); return jsonResponse({ message: '角色已更新' }, 200, request); }
        }

        // --- ★ 公告系统 ★ ---
        if (pathParts[0] === 'announcements') {
            if (request.method === 'GET' && pathParts[1] === 'my') { const { results } = await env.DB.prepare("SELECT * FROM Announcements WHERE (user_id = ? OR user_id IS NULL) AND is_read = 0 ORDER BY created_at DESC").bind(user.id).all(); return jsonResponse(results, 200, request); }
            if (request.method === 'PUT' && pathParts[1] && pathParts[2] === 'read') { await env.DB.prepare("UPDATE Announcements SET is_read = 1 WHERE id = ? AND (user_id = ? OR user_id IS NULL)").bind(pathParts[1], user.id).run(); return jsonResponse(null, 204, request); }
             if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') { const { userId, content, isGlobal } = await request.json(); const targetId = isGlobal ? null : userId; await env.DB.prepare("INSERT INTO Announcements (user_id, content) VALUES (?, ?)").bind(targetId, content).run(); return jsonResponse({ message: '公告已发送' }, 201, request); }
        }

        // --- ★ 动态链接收藏API ★ ---
        if (pathParts[0] === 'favorites') {
            const userId = user.id;
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare(`
                    SELECT f.id, f.novel_id, s.subdomain, f.chapter_index, f.chapter_title, f.created_at
                    FROM FavoriteChapters f
                    JOIN Sites s ON f.novel_id = s.name
                    WHERE f.user_id = ? AND s.type = 'novel'
                    ORDER BY f.novel_id, f.chapter_index
                `).bind(userId).all();
                return jsonResponse(results, 200, request);
            }
            if (request.method === 'POST') { /* ... (保持不变) */ }
            if (request.method === 'DELETE') {
                const idToDelete = pathParts[1]; // 现在我们按收藏ID删除
                if (idToDelete) { await env.DB.prepare("DELETE FROM FavoriteChapters WHERE id = ? AND user_id = ?").bind(idToDelete, userId).run(); }
                return jsonResponse(null, 204, request);
            }
        }
        
        // --- 进度API (无变化) ---
        if (pathParts[0] === 'progress' && pathParts[1]) { /* ... */ }

        return jsonResponse({ error: `API路由未找到` }, 404, request);
    } catch (e) { console.error("API Error:", e); return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request); }
}

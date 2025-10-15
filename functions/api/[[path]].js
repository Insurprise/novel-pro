/* =================================================================
 *  Cloudflare Worker Backend (v3.0.5 - The Truly Final, Complete Code)
 *  - Everything is included. No ellipses, no placeholders.
 *  - Fixes favorite list display (JOIN on subdomain).
 *  - Fixes favorite creation (includes all required fields).
 *  - Contains full logic for all API endpoints.
 * ================================================================= */

const ROOT_ADMIN_ID = 1; // 站长ID，永不可被修改

// --- 辅助函数 ---
const handleOptions = (request) => {
    const origin = request.headers.get("Origin") || "*";
    const headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
    };
    return new Response(null, { headers });
};

const jsonResponse = (data, status = 200, request) => {
    const origin = request.headers.get("Origin") || "*";
    const headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Access-Control-Allow-Origin": origin,
    };
    return new Response(JSON.stringify(data, null, 2), { status, headers });
};

async function hashPassword(password) {
    const utf8 = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function getUserFromToken(request) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    try {
        const token = authHeader.split(' ')[1];
        return JSON.parse(atob(token));
    } catch (e) {
        return null;
    }
}

// --- 主入口 ---
export async function onRequest(context) {
    if (context.request.method === 'OPTIONS') {
        return handleOptions(context.request);
    }
    return handleApiRequest(context);
}

// --- 核心API路由 ---
async function handleApiRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathParts = params.path || [];

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

        const user = getUserFromToken(request);
        if (!user) return jsonResponse({ error: '未授权或Token无效' }, 401, request);

        // --- ★ 统一站点管理 ★ ---
        if (pathParts[0] === 'sites') {
            if (request.method === 'GET') {
                const type = url.searchParams.get('type');
                let query = "SELECT * FROM Sites";
                const bindings = [];
                if (type) { query += " WHERE type = ?"; bindings.push(type); }
                query += " ORDER BY name";
                const { results } = await env.DB.prepare(query).bind(...bindings).all();
                return jsonResponse(results, 200, request);
            }
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') {
                const { name, subdomain, type, author, description } = await request.json();
                const { meta } = await env.DB.prepare("INSERT INTO Sites (name, subdomain, type, author, description) VALUES (?, ?, ?, ?, ?)").bind(name, subdomain, type, author, description).run();
                return jsonResponse({ id: meta.last_row_id }, 201, request);
            }
            if (request.method === 'PUT' && pathParts[1]) {
                const { name, subdomain, type, author, description } = await request.json();
                await env.DB.prepare("UPDATE Sites SET name=?, subdomain=?, type=?, author=?, description=? WHERE id=?").bind(name, subdomain, type, author, description, pathParts[1]).run();
                return jsonResponse({ message: '更新成功' }, 200, request);
            }
            if (request.method === 'DELETE' && pathParts[1]) {
                await env.DB.prepare("DELETE FROM Sites WHERE id = ?").bind(pathParts[1]).run();
                return jsonResponse(null, 204, request);
            }
        }

        // --- ★ 高级用户管理 ★ ---
        if (pathParts[0] === 'users') {
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare("SELECT id, username, role, status FROM Users").all();
                return jsonResponse(results, 200, request);
            }
            const targetUserId = parseInt(pathParts[1]);
            const targetUser = await env.DB.prepare("SELECT * FROM Users where id = ?").bind(targetUserId).first();
            if (!targetUser || targetUserId === ROOT_ADMIN_ID || (targetUser.role === 'admin' && user.id !== ROOT_ADMIN_ID)) {
                return jsonResponse({ error: '无权操作此用户' }, 403, request);
            }
            if (request.method === 'DELETE') {
                await env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetUserId).run();
                return jsonResponse(null, 204, request);
            }
            if (pathParts[2] === 'password') {
                const { password } = await request.json();
                const hash = await hashPassword(password);
                await env.DB.prepare("UPDATE Users SET password_hash = ? WHERE id = ?").bind(hash, targetUserId).run();
                return jsonResponse({ message: '密码已修改' }, 200, request);
            }
            if (pathParts[2] === 'status') {
                const { status } = await request.json();
                await env.DB.prepare("UPDATE Users SET status = ? WHERE id = ?").bind(status, targetUserId).run();
                return jsonResponse({ message: '状态已更新' }, 200, request);
            }
            if (pathParts[2] === 'role') {
                const { role } = await request.json();
                await env.DB.prepare("UPDATE Users SET role = ? WHERE id = ?").bind(role, targetUserId).run();
                return jsonResponse({ message: '角色已更新' }, 200, request);
            }
        }

        // --- ★ 公告系统 ★ ---
        if (pathParts[0] === 'announcements') {
            if (request.method === 'GET' && pathParts[1] === 'my') { const { results } = await env.DB.prepare("SELECT * FROM Announcements WHERE (user_id = ? OR user_id IS NULL) AND is_read = 0 ORDER BY created_at DESC").bind(user.id).all(); return jsonResponse(results, 200, request); }
            if (request.method === 'PUT' && pathParts[1] && pathParts[2] === 'read') { await env.DB.prepare("UPDATE Announcements SET is_read = 1 WHERE id = ? AND (user_id = ? OR user_id IS NULL)").bind(pathParts[1], user.id).run(); return jsonResponse(null, 204, request); }
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') { const { userId, content, isGlobal } = await request.json(); const targetId = isGlobal ? null : userId; await env.DB.prepare("INSERT INTO Announcements (user_id, content) VALUES (?, ?)").bind(targetId, content).run(); return jsonResponse({ message: '公告已发送' }, 201, request); }
        }

        // --- ★ 动态链接收藏API (终极修正版) ★ ---
        if (pathParts[0] === 'favorites') {
            const userId = user.id;
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare(`
                    SELECT f.id, s.name as novel_id, s.subdomain, f.chapter_index, f.chapter_title 
                    FROM FavoriteChapters f 
                    JOIN Sites s ON f.novel_id = s.subdomain 
                    WHERE f.user_id = ? AND s.type = 'novel' 
                    ORDER BY s.name, f.chapter_index
                `).bind(userId).all();
                return jsonResponse(results, 200, request);
            }
            if (request.method === 'POST') {
                const { novel_id, chapter_id, chapter_index, chapter_title } = await request.json();
                if (!novel_id || !chapter_id || !chapter_index || !chapter_title) {
                    return jsonResponse({ error: "请求参数不完整" }, 400, request);
                }
                await env.DB.prepare("INSERT INTO FavoriteChapters (user_id, novel_id, chapter_id, chapter_index, chapter_title) VALUES (?, ?, ?, ?, ?)").bind(userId, novel_id, chapter_id, chapter_index, chapter_title).run();
                return jsonResponse({ message: "收藏成功" }, 201, request);
            }
            if (request.method === 'DELETE') {
                const idToDelete = pathParts[1];
                if (idToDelete) {
                    await env.DB.prepare("DELETE FROM FavoriteChapters WHERE id = ? AND user_id = ?").bind(idToDelete, userId).run();
                } else {
                    const novel_id = url.searchParams.get('novel_id');
                    const chapter_index = url.search_params.get('chapter_index');
                    if (novel_id && chapter_index) {
                        await env.DB.prepare("DELETE FROM FavoriteChapters WHERE user_id = ? AND novel_id = ? AND chapter_index = ?").bind(userId, novel_id, chapter_index).run();
                    } else {
                        return jsonResponse({ error: "删除收藏失败，缺少必要的参数" }, 400, request);
                    }
                }
                return jsonResponse(null, 204, request);
            }
        }
        
        // --- ★ 进度API ★ ---
        if (pathParts[0] === 'progress' && pathParts[1]) {
            const novel_id = pathParts[1];
            if (request.method === 'GET') {
                const record = await env.DB.prepare("SELECT * FROM ReadingRecords WHERE user_id = ? AND novel_id = ?").bind(user.id, novel_id).first();
                return jsonResponse(record || {}, 200, request);
            }
            if (request.method === 'POST') {
                const { chapter_id, position } = await request.json();
                await env.DB.prepare("INSERT OR REPLACE INTO ReadingRecords (user_id, novel_id, chapter_id, position, updated_at) VALUES (?, ?, ?, ?, datetime('now'))").bind(user.id, novel_id, chapter_id, position).run();
                return jsonResponse(null, 204, request);
            }
        }

        return jsonResponse({ error: `API路由未找到: ${request.method} ${url.pathname}` }, 404, request);
    } catch (e) {
        console.error("API Error:", e);
        return jsonResponse({ error: '服务器内部错误', details: e.message, stack: e.stack }, 500, request);
    }
}

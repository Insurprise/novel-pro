/* =================================================================
 * Cloudflare Worker Backend (v18.0.0 - Full Feature Set)
 * 支持:
 * 1. 登录 (POST /login)
 * 2. 站点管理 (CRUD /sites)
 * 3. 用户管理 (GET /users, DELETE /users/:id, PUT /users/:id/...)
 * 4. 管理员创建用户 (POST /users)
 * 5. 公告/私信 (POST /announcements)
 * 6. 移除了公开注册接口
 * ================================================================= */

const ROOT_ADMIN_ID = 1;

const handleOptions = (request) => { 
    const origin = request.headers.get("Origin") || "*"; 
    const headers = { 
        "Access-Control-Allow-Origin": origin, 
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", 
        "Access-Control-Allow-Headers": "Content-Type, Authorization", 
        "Access-Control-Max-Age": "86400" 
    }; 
    return new Response(null, { headers }); 
};

const jsonResponse = (data, status = 200, request) => { 
    const origin = request.headers.get("Origin") || "*"; 
    const headers = { 
        "Content-Type": "application/json;charset=UTF-8", 
        "Access-Control-Allow-Origin": origin 
    }; 
    if (status === 204) return new Response(null, { status, headers });
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
    } catch (e) { return null; } 
}

export async function onRequest(context) { 
    if (context.request.method === 'OPTIONS') return handleOptions(context.request); 
    return handleApiRequest(context); 
}

async function handleApiRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathParts = params.path || [];

    try {
        // [Public] Login
        if (pathParts[0] === 'login') {
            const { username, password } = await request.json();
            if (!username || !password) return jsonResponse({ error: '请输入用户名和密码' }, 400, request);

            const password_hash = await hashPassword(password);
            const userDb = await env.DB.prepare("SELECT id, username, role, status FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first();
            
            if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request);
            if (userDb.status === 'banned') return jsonResponse({ error: '账户已被封禁' }, 403, request);
            
            const token = btoa(JSON.stringify({ id: userDb.id, username: userDb.username, role: userDb.role }));
            return jsonResponse({ token, user: { id: userDb.id, username: userDb.username, role: userDb.role } }, 200, request);
        }

        // [Auth Check]
        const user = getUserFromToken(request);
        if (!user || !user.id) return jsonResponse({ error: 'Session expired', status: 401 }, 401, request);
        const userId = user.id;
        
        // [API] Users
        if (pathParts[0] === 'users') {
            if (request.method === 'GET') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const { results } = await env.DB.prepare("SELECT id, username, role, status FROM Users").all();
                return jsonResponse(results, 200, request);
            }

            // Admin Create User
            if (request.method === 'POST') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const { username, password, role } = await request.json();
                if (!username || !password) return jsonResponse({ error: '信息不完整' }, 400, request);
                
                const exists = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first();
                if (exists) return jsonResponse({ error: '用户名已存在' }, 409, request);
                
                const phash = await hashPassword(password);
                const newRole = role === 'admin' ? 'admin' : 'user';
                await env.DB.prepare("INSERT INTO Users (username, password_hash, role, status) VALUES (?, ?, ?, 'active')").bind(username, phash, newRole).run();
                return jsonResponse({ message: 'Created' }, 201, request);
            }

            if (request.method === 'PUT' && pathParts[1]) {
                const targetId = parseInt(pathParts[1]);
                const action = pathParts[2]; 
                const body = await request.json();

                if (action === 'password') {
                    if (targetId !== userId && user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                    if (!body.password) return jsonResponse({ error: '密码不能为空' }, 400, request);
                    const phash = await hashPassword(body.password);
                    await env.DB.prepare("UPDATE Users SET password_hash = ? WHERE id = ?").bind(phash, targetId).run();
                    return jsonResponse({ message: 'Success' }, 200, request);
                } 
                
                if (action === 'status' || action === 'role') {
                    if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                    if (targetId === ROOT_ADMIN_ID) return jsonResponse({ error: '无法修改根管理员' }, 403, request);
                    if (action === 'status') await env.DB.prepare("UPDATE Users SET status = ? WHERE id = ?").bind(body.status, targetId).run();
                    if (action === 'role') await env.DB.prepare("UPDATE Users SET role = ? WHERE id = ?").bind(body.role, targetId).run();
                    return jsonResponse({ message: 'Success' }, 200, request);
                }
            }
            
            if (request.method === 'DELETE' && pathParts[1]) {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const targetId = parseInt(pathParts[1]);
                if (targetId === ROOT_ADMIN_ID || targetId === userId) return jsonResponse({ error: '无法删除该账户' }, 403, request);
                await env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetId).run();
                return jsonResponse({ message: 'Deleted' }, 200, request);
            }
        }

        // [API] Sites
        if (pathParts[0] === 'sites') { 
             if (request.method === 'GET') { 
                const type = url.searchParams.get('type'); 
                const stmt = type ? env.DB.prepare("SELECT * FROM Sites WHERE type = ? ORDER BY name").bind(type) : env.DB.prepare("SELECT * FROM Sites ORDER BY name");
                const { results } = await stmt.all(); 
                return jsonResponse(results, 200, request); 
            } 
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request); 
            if (request.method === 'POST') { 
                const d = await request.json(); 
                await env.DB.prepare("INSERT INTO Sites (name, subdomain, type, author, description) VALUES (?, ?, ?, ?, ?)").bind(d.name, d.subdomain, d.type, d.author, d.description).run(); 
                return jsonResponse({ message: 'Success' }, 201, request); 
            } 
            if (request.method === 'PUT' && pathParts[1]) { 
                const d = await request.json(); 
                await env.DB.prepare("UPDATE Sites SET name=?, subdomain=?, type=?, author=?, description=? WHERE id=?").bind(d.name, d.subdomain, d.type, d.author, d.description, pathParts[1]).run(); 
                return jsonResponse({ message: 'Success' }, 200, request); 
            } 
            if (request.method === 'DELETE' && pathParts[1]) { 
                await env.DB.prepare("DELETE FROM Sites WHERE id = ?").bind(pathParts[1]).run(); 
                return jsonResponse(null, 204, request); 
            } 
        }

        // [API] Progress
        if (pathParts[0] === 'progress') {
            if (request.method === 'POST') {
                const { novel_id, chapter_id, position } = await request.json();
                const stmt = `INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id=excluded.chapter_id, position=excluded.position, updated_at=CURRENT_TIMESTAMP`;
                await env.DB.prepare(stmt).bind(userId, novel_id, chapter_id, position).run();
                return jsonResponse({ message: 'saved' }, 200, request);
            }
            if (request.method === 'GET' && pathParts[1]) {
                const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id = ? AND novel_id = ?").bind(userId, pathParts[1]).first();
                return jsonResponse(record || null, 200, request);
            }
        }

        // [API] Announcements
        if (pathParts[0] === 'announcements') { 
            if (request.method === 'GET') { 
                const { results } = await env.DB.prepare("SELECT id, content FROM Announcements WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC").bind(userId).all(); 
                return jsonResponse(results, 200, request); 
            } 
            if (request.method === 'PUT' && pathParts[2] === 'read') {
                 await env.DB.prepare("UPDATE Announcements SET is_read = 1 WHERE id = ? AND user_id = ?").bind(pathParts[1], userId).run(); 
                 return jsonResponse(null, 204, request);
            }
            if (request.method === 'POST') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const { userId: targetUid, content, isGlobal } = await request.json();
                if (isGlobal) {
                    const allUsers = await env.DB.prepare("SELECT id FROM Users").all();
                    const stmt = env.DB.prepare("INSERT INTO Announcements (user_id, content, is_read) VALUES (?, ?, 0)");
                    const batch = allUsers.results.map(u => stmt.bind(u.id, content));
                    await env.DB.batch(batch);
                } else if (targetUid) {
                    await env.DB.prepare("INSERT INTO Announcements (user_id, content, is_read) VALUES (?, ?, 0)").bind(targetUid, content).run();
                }
                return jsonResponse({ message: 'Sent' }, 201, request);
            }
        }

        return jsonResponse({ error: `Not Found` }, 404, request);
    } catch (e) {
        return jsonResponse({ error: 'Server Error', details: e.message }, 500, request);
    }
}

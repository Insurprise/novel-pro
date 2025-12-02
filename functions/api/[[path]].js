/* =================================================================
 * Cloudflare Worker Backend (v15.0.0 - Full Security Version)
 * 包含所有 API 路由，移除公开注册，强化权限控制
 * ================================================================= */

const ROOT_ADMIN_ID = 1;

// --- Helper Functions ---
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
    // 对于204状态码，不返回任何内容
    if (status === 204) {
        return new Response(null, { status, headers });
    }
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

// --- Main Entry ---
export async function onRequest(context) { 
    if (context.request.method === 'OPTIONS') { 
        return handleOptions(context.request); 
    } 
    return handleApiRequest(context); 
}

// --- Core API Router ---
async function handleApiRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathParts = params.path || [];

    try {
        // --- Public Routes (仅登录) ---
        if (pathParts[0] === 'login') {
            const { username, password } = await request.json();
            if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request);

            const password_hash = await hashPassword(password);
            const userDb = await env.DB.prepare("SELECT id, username, role, status FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first();
            
            if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request);
            if (userDb.status === 'banned') return jsonResponse({ error: '您的账户已被封禁' }, 403, request);
            
            const token = btoa(JSON.stringify({ id: userDb.id, username: userDb.username, role: userDb.role }));
            return jsonResponse({ token, user: { id: userDb.id, username: userDb.username, role: userDb.role } }, 200, request);
        }

        // 【安全变更】移除了 Public Register 路由，现在注册仅限管理员在后台操作

        // --- Authenticated Routes (所有后续操作都需要 Token) ---
        const user = getUserFromToken(request);
        if (!user || !user.id) return jsonResponse({ error: '未授权或登录超时', status: 401 }, 401, request);
        const userId = user.id;
        
        // [USERS API] - 用户管理
        if (pathParts[0] === 'users') {
            // 获取用户列表 (管理员)
            if (request.method === 'GET') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const { results } = await env.DB.prepare("SELECT id, username, role, status, created_at FROM Users").all();
                return jsonResponse(results, 200, request);
            }

            // 管理员手动创建用户
            if (request.method === 'POST') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const { username, password, role } = await request.json();
                if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request);
                
                const existingUser = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first();
                if (existingUser) return jsonResponse({ error: '用户名已存在' }, 409, request);
                
                const password_hash = await hashPassword(password);
                const newRole = role === 'admin' ? 'admin' : 'user';
                
                await env.DB.prepare("INSERT INTO Users (username, password_hash, role, status) VALUES (?, ?, ?, ?)").bind(username, password_hash, newRole, 'active').run();
                return jsonResponse({ message: `用户 ${username} 创建成功` }, 201, request);
            }

            // 修改用户信息
            if (request.method === 'PUT' && pathParts[1]) {
                const targetUserId = parseInt(pathParts[1]);
                const action = pathParts[2]; // password, status, role
                
                // 权限检查：普通用户只能修改自己的密码
                if (action === 'password' && targetUserId !== userId && user.role !== 'admin') {
                    return jsonResponse({ error: '无权操作' }, 403, request);
                }
                // 权限检查：只有管理员可以修改状态和角色
                if ((action === 'status' || action === 'role') && user.role !== 'admin') {
                    return jsonResponse({ error: '无权操作' }, 403, request);
                }
                
                const data = await request.json();
                
                if (action === 'password') {
                    if (!data.password) return jsonResponse({ error: '密码不能为空' }, 400, request);
                    const password_hash = await hashPassword(data.password);
                    await env.DB.prepare("UPDATE Users SET password_hash = ? WHERE id = ?").bind(password_hash, targetUserId).run();
                    return jsonResponse({ message: '密码修改成功' }, 200, request);
                } 
                
                // 管理员操作保护：不能修改根管理员的状态或角色
                if (targetUserId === ROOT_ADMIN_ID && (action === 'status' || action === 'role')) {
                     return jsonResponse({ error: '无法修改根管理员的权限或状态' }, 403, request);
                }

                if (action === 'status') {
                    await env.DB.prepare("UPDATE Users SET status = ? WHERE id = ?").bind(data.status, targetUserId).run();
                    return jsonResponse({ message: '状态已更新' }, 200, request);
                } else if (action === 'role') {
                    await env.DB.prepare("UPDATE Users SET role = ? WHERE id = ?").bind(data.role, targetUserId).run();
                    return jsonResponse({ message: '角色已更新' }, 200, request);
                }
            }
            
            // 删除用户
            if (request.method === 'DELETE' && pathParts[1]) {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const targetUserId = parseInt(pathParts[1]);
                
                // 保护根管理员和自己
                if (targetUserId === ROOT_ADMIN_ID) return jsonResponse({ error: '无法删除根管理员账户' }, 403, request);
                if (targetUserId === userId) return jsonResponse({ error: '无法删除自己的账户' }, 403, request);
                
                // 级联删除相关数据
                await env.DB.prepare("DELETE FROM FavoriteChapters WHERE user_id = ?").bind(targetUserId).run();
                await env.DB.prepare("DELETE FROM ReadingRecords WHERE user_id = ?").bind(targetUserId).run();
                await env.DB.prepare("DELETE FROM Announcements WHERE user_id = ?").bind(targetUserId).run();
                await env.DB.prepare("DELETE FROM Users WHERE id = ?").bind(targetUserId).run();
                return jsonResponse({ message: '用户已删除' }, 200, request);
            }
        }

        // [SITES API] - 站点管理 (NavLinks)
        if (pathParts[0] === 'sites') { 
             if (request.method === 'GET') { 
                const type = url.searchParams.get('type'); 
                const { results } = await env.DB.prepare(`SELECT * FROM Sites ${type ? 'WHERE type = ?' : ''} ORDER BY name`).bind(...(type ? [type] : [])).all(); 
                return jsonResponse(results, 200, request); 
            } 
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request); 
            
            if (request.method === 'POST') { 
                const d = await request.json(); 
                await env.DB.prepare("INSERT INTO Sites (name, subdomain, type, author, description) VALUES (?, ?, ?, ?, ?)").bind(d.name, d.subdomain, d.type, d.author, d.description).run(); 
                return jsonResponse({ message: '创建成功' }, 201, request); 
            } 
            if (request.method === 'PUT' && pathParts[1]) { 
                const d = await request.json(); 
                await env.DB.prepare("UPDATE Sites SET name=?, subdomain=?, type=?, author=?, description=? WHERE id=?").bind(d.name, d.subdomain, d.type, d.author, d.description, pathParts[1]).run(); 
                return jsonResponse({ message: '更新成功' }, 200, request); 
            } 
            if (request.method === 'DELETE' && pathParts[1]) { 
                await env.DB.prepare("DELETE FROM Sites WHERE id = ?").bind(pathParts[1]).run(); 
                return jsonResponse(null, 204, request); 
            } 
        }

        // [FAVORITES API] - 收藏管理
        if (pathParts[0] === 'favorites') { 
            if (request.method === 'GET') { 
                const { results } = await env.DB.prepare("SELECT novel_id, chapter_id FROM FavoriteChapters WHERE user_id = ?").bind(userId).all(); 
                return jsonResponse(results, 200, request); 
            } 
            if (request.method === 'POST') { 
                const { novel_id, chapter_id, chapter_index, chapter_title } = await request.json(); 
                await env.DB.prepare("INSERT INTO FavoriteChapters (user_id, novel_id, chapter_id, chapter_ind, chapter_title) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, novel_id, chapter_id) DO NOTHING").bind(userId, novel_id, chapter_id, chapter_index, chapter_title).run(); 
                return jsonResponse({ message: '收藏成功' }, 201, request); 
            } 
            if (request.method === 'DELETE') { 
                const { novel_id, chapter_id } = await request.json(); 
                await env.DB.prepare("DELETE FROM FavoriteChapters WHERE user_id = ? AND novel_id = ? AND chapter_id = ?").bind(userId, novel_id, chapter_id).run(); 
                return jsonResponse(null, 204, request); 
            } 
        }

        // [READING PROGRESS API] - 阅读进度
        if (pathParts[0] === 'progress') {
            if (request.method === 'POST') {
                const { novel_id, chapter_id, position } = await request.json();
                if (!novel_id) return jsonResponse({ error: 'novel_id is required' }, 400, request);
                // 使用 upsert 逻辑：如果存在则更新，不存在则插入
                const stmt = `INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id=excluded.chapter_id, position=excluded.position, updated_at=CURRENT_TIMESTAMP`;
                await env.DB.prepare(stmt).bind(userId, novel_id, chapter_id, position).run();
                return jsonResponse({ message: '进度已保存' }, 200, request);
            }
            if (request.method === 'GET' && pathParts[1]) {
                const novel_id = pathParts[1];
                const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id = ? AND novel_id = ?").bind(userId, novel_id).first();
                return jsonResponse(record || null, 200, request);
            }
        }

        // [ANNOUNCEMENTS API] - 公告系统
        if (pathParts[0] === 'announcements') { 
            // 获取未读公告
            if (request.method === 'GET') { 
                const { results } = await env.DB.prepare("SELECT id, content FROM Announcements WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC").bind(userId).all(); 
                return jsonResponse(results, 200, request); 
            } 
            // 标记为已读
            if (request.method === 'PUT' && pathParts[1] && pathParts[2] === 'read') { 
                await env.DB.prepare("UPDATE Announcements SET is_read = 1 WHERE id = ? AND user_id = ?").bind(pathParts[1], userId).run(); 
                return jsonResponse(null, 204, request); 
            }
            // 发送公告 (仅管理员)
            if (request.method === 'POST') {
                if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
                const { userId: targetUserId, content, isGlobal } = await request.json();
                
                if (isGlobal) {
                    // 全局公告：给所有用户插入一条
                    const users = await env.DB.prepare("SELECT id FROM Users").all();
                    // 注意：对于大量用户，这可能需要改为批量插入或优化逻辑
                    const stmt = env.DB.prepare("INSERT INTO Announcements (user_id, content, is_read) VALUES (?, ?, 0)");
                    const batch = users.results.map(u => stmt.bind(u.id, content));
                    await env.DB.batch(batch);
                    return jsonResponse({ message: '全局公告已发送' }, 201, request);
                } else if (targetUserId) {
                    // 私信
                    await env.DB.prepare("INSERT INTO Announcements (user_id, content, is_read) VALUES (?, ?, 0)").bind(targetUserId, content).run();
                    return jsonResponse({ message: '私信已发送' }, 201, request);
                } else {
                    return jsonResponse({ error: '参数错误' }, 400, request);
                }
            }
        }

        // 兜底：未匹配到路由
        return jsonResponse({ error: `API路由未找到: ${request.method} ${url.pathname}` }, 404, request);

    } catch (e) {
        console.error("API Error:", e);
        return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request);
    }
}

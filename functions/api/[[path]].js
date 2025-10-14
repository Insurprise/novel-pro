/* =================================================================
 *  Cloudflare Worker Backend (FINAL & COMPLETE VERSION)
 *  文件位置: /functions/api/[[path]].js
 *  更新: 添加了“更新小说” (PUT /api/novels/:id) 的功能。
 *  这是包含所有功能的最终版本。
 * ================================================================= */

// --- 1. 配置允许访问的源 ---
const allowedOrigins = [
    "https://novel-pro.20100505.xyz",
    "https://santi.20100505.xyz",
];

// --- 2. CORS & JSON 响应处理器 ---
function handleOptions(request) { /* (代码未变) */ }
function jsonResponse(data, status = 200, request) { /* (代码未变) */ }
function corsHeaders(request) { /* (代码未变) */ }
// --- (为简洁起见，省略未修改的函数体，请使用您文件里已有的) ---


// --- 3. API 主入口 ---
export async function onRequest(context) {
    const { request } = context;
    if (request.method === "OPTIONS") {
        return handleOptions(request);
    }
    return await handleApiRequest(context);
}

// --- 4. 核心API逻辑 ---
async function handleApiRequest(context) {
    const { request, env } = context;
    const pathParts = context.params.path || [];

    // --- 辅助函数 ---
    const hashPassword = async (password) => { /* (代码未变) */ };
    const getUserFromToken = (req) => { /* (代码未变) */ };
    const user = getUserFromToken(request);

    try {
        // --- 公共路由 (无需登录) ---
        if (pathParts[0] === 'register' && request.method === 'POST') { /* (代码未变) */ }
        if (pathParts[0] === 'login' && request.method === 'POST') { /* (代码未变) */ }
        
        // --- 需要登录 ---
        if (!user) return jsonResponse({ error: '未授权访问' }, 401, request);
        
        // --- 导航链接管理 (管理员权限) ---
        if (pathParts[0] === 'navlinks') { /* (代码未变) */ }
        
        // --- 小说管理 (管理员权限) ---
        if (pathParts[0] === 'novels') {
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            
            if (request.method === 'GET') { /* (代码未变) */ }
            if (request.method === 'POST') { /* (代码未变) */ }
            
            // ★★★ 本次新增的功能 ★★★
            // PUT /api/novels/:id (更新一本已存在的小说)
            if (request.method === 'PUT' && pathParts[1]) {
                const novelId = pathParts[1];
                const { title, author } = await request.json();
                if (!title) return jsonResponse({ error: '标题不能为空' }, 400, request);

                await env.DB.prepare("UPDATE Novels SET title = ?, author = ? WHERE id = ?")
                    .bind(title, author, novelId)
                    .run();
                
                return jsonResponse({ id: novelId, title, author }, 200, request);
            }
            // ★★★ 新增结束 ★★★

            if (request.method === 'DELETE' && pathParts[1]) { /* (代码未变) */ }
        }

        // --- 用户阅读进度 ---
        if (pathParts[0] === 'progress' && pathParts[1]) { /* (代码未变) */ }

        // 如果以上路由都没有匹配，则返回404
        return jsonResponse({ error: `API 路由未找到: /api/${pathParts.join('/')}` }, 404, request);

    } catch (e) {
        console.error(e.message, e.stack);
        return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request);
    }
}


/* =================================================================
 * 完整的辅助函数 (请确保您的文件里包含这些)
 * ================================================================= */

function handleOptions(request) {
    const origin = request.headers.get("Origin");
    if (allowedOrigins.includes(origin)) {
        return new Response(null, { status: 204, headers: {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "86400",
        }});
    } else { return new Response("Forbidden", { status: 403 }); }
}

function jsonResponse(data, status = 200, request) {
    const origin = request.headers.get("Origin");
    const headers = { "Content-Type": "application/json;charset=UTF-8" };
    if (allowedOrigins.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
    return new Response(JSON.stringify(data, null, 2), { status, headers });
}

function corsHeaders(request) {
    const origin = request.headers.get("Origin");
    const headers = {};
    if (allowedOrigins.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
    return headers;
}
 
async function handleApiRequest(context) {
    const { request, env } = context;
    const pathParts = context.params.path || [];

    const hashPassword = async (password) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + "a-very-strong-and-secret-salt");
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const getUserFromToken = (req) => {
        const authHeader = req.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
        const token = authHeader.substring(7);
        try { return JSON.parse(atob(token)); } catch (e) { return null; }
    };
    
    const user = getUserFromToken(request);

    try {
        if (pathParts[0] === 'register' && request.method === 'POST') {
             const { username, password } = await request.json();
             if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request);
             const existingUser = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first();
             if (existingUser) return jsonResponse({ error: '用户名已存在' }, 409, request);
             const password_hash = await hashPassword(password);
             const userCountResult = await env.DB.prepare("SELECT COUNT(id) as count FROM Users").first();
             const role = (!userCountResult || userCountResult.count === 0) ? 'admin' : 'user';
             await env.DB.prepare("INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)")
                 .bind(username, password_hash, role).run();
             return jsonResponse({ message: '用户注册成功' }, 201, request);
        }

        if (pathParts[0] === 'login' && request.method === 'POST') {
            const { username, password } = await request.json();
            const password_hash = await hashPassword(password);
            const userDb = await env.DB.prepare("SELECT id, username, role FROM Users WHERE username = ? AND password_hash = ?")
                .bind(username, password_hash).first();
            if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request);
            const userData = { userId: userDb.id, username: userDb.username, role: userDb.role, timestamp: Date.now() };
            const sessionToken = btoa(JSON.stringify(userData));
            return jsonResponse({ token: sessionToken, user: userData }, 200, request);
        }

        if (!user) return jsonResponse({ error: '未授权访问' }, 401, request);
        
        if (pathParts[0] === 'navlinks') {
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare("SELECT id, name, subdomain FROM NavLinks ORDER BY name").all();
                return jsonResponse(results, 200, request);
            }
             if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') {
                const { name, subdomain } = await request.json();
                const { meta } = await env.DB.prepare("INSERT INTO NavLinks (name, subdomain) VALUES (?, ?)")
                    .bind(name, subdomain).run();
                return jsonResponse({ id: meta.last_row_id, name, subdomain }, 201, request);
            }
            if (request.method === 'PUT' && pathParts[1]) {
                const { name, subdomain } = await request.json();
                await env.DB.prepare("UPDATE NavLinks SET name = ?, subdomain = ? WHERE id = ?")
                    .bind(name, subdomain, pathParts[1]).run();
                return jsonResponse({ message: '更新成功' }, 200, request);
            }
            if (request.method === 'DELETE' && pathParts[1]) {
                 await env.DB.prepare("DELETE FROM NavLinks WHERE id = ?").bind(pathParts[1]).run();
                 return new Response(null, { status: 204, headers: corsHeaders(request) });
            }
        }
        
        if (pathParts[0] === 'novels') {
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            
            if (request.method === 'GET') {
                const { results } = await env.DB.prepare("SELECT id, title, author FROM Novels ORDER BY id").all();
                return jsonResponse(results, 200, request);
            }
            
            if (request.method === 'POST') {
                const { id, title, author } = await request.json();
                if (!id || !title) return jsonResponse({ error: 'ID和标题不能为空' }, 400, request);
                await env.DB.prepare("INSERT INTO Novels (id, title, author) VALUES (?, ?, ?)")
                    .bind(id, title, author).run();
                return jsonResponse({ id, title, author }, 201, request);
            }
            
            if (request.method === 'PUT' && pathParts[1]) {
                const novelId = pathParts[1];
                const { title, author } = await request.json();
                if (!title) return jsonResponse({ error: '标题不能为空' }, 400, request);
                await env.DB.prepare("UPDATE Novels SET title = ?, author = ? WHERE id = ?")
                    .bind(title, author, novelId).run();
                return jsonResponse({ id: novelId, title, author }, 200, request);
            }

             if (request.method === 'DELETE' && pathParts[1]) {
                 await env.DB.prepare("DELETE FROM Novels WHERE id = ?").bind(pathParts[1]).run();
                 return new Response(null, { status: 204, headers: corsHeaders(request) });
            }
        }

        if (pathParts[0] === 'progress' && pathParts[1]) {
            const novel_id = pathParts[1];
            if (request.method === 'POST') {
                const { chapter_id, position } = await request.json();
                 await env.DB.prepare(`
                    INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position) VALUES (?1, ?2, ?3, ?4) 
                    ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id = ?3, position = ?4, updated_at = CURRENT_TIMESTAMP
                 `).bind(user.userId, novel_id, chapter_id, position).run();
                return jsonResponse({ message: '进度已保存' }, 200, request);
            }
             if (request.method === 'GET') {
                const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id = ? AND novel_id = ?")
                    .bind(user.userId, novel_id).first();
                if (!record) return jsonResponse({ error: "No record found" }, 404, request);
                return jsonResponse(record, 200, request);
            }
        }

        return jsonResponse({ error: `API 路由未找到: /api/${pathParts.join('/')}` }, 404, request);

    } catch (e) {
        console.error(e.message, e.stack);
        return jsonResponse({ error: '服务器内部错误', details: e.message }, 500, request);
    }
}

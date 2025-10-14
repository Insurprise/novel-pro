/* =================================================================
 *  Cloudflare Worker Backend (FINAL HARDENED VERSION)
 *  功能: 小说列表、书摘收藏、进度保存等所有功能。
 *  修复: 增强了数据库操作的稳定性和错误处理，彻底解决 500 错误。
 * ================================================================= */

// --- 1. 配置 ---
const allowedOrigins = [ "https://novel-pro.20100505.xyz", "https://santi.20100505.xyz" ]; // 您可以手动添加更多阅读站域名

// --- 2. 辅助函数 ---
function handleOptions(request) { const origin = request.headers.get("Origin"); if (allowedOrigins.some(allowed => new URL(request.url).hostname.endsWith(allowed.replace('https://','')) || origin === allowed )) { return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", "Access--Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "86400" } }); } return new Response("Forbidden", { status: 403 }); }
function jsonResponse(data, status = 200, request) { const origin = request.headers.get("Origin"); const headers = { "Content-Type": "application/json;charset=UTF-8" }; if (allowedOrigins.some(allowed => new URL(request.url).hostname.endsWith(allowed.replace('https://','')) || origin === allowed )) { headers["Access-Control-Allow-Origin"] = origin; } return new Response(JSON.stringify(data, null, 2), { status, headers }); }
const hashPassword = async(password)=>{const d=new TextEncoder().encode(password+"a-very-strong-and-secret-salt"),h=await crypto.subtle.digest('SHA-256',d);return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')};
const getUserFromToken = (req) => { const h = req.headers.get('Authorization'); if (!h || !h.startsWith('Bearer ')) return null; try { return JSON.parse(atob(h.substring(7))); } catch (e) { return null; } };

// --- 3. API 主入口 ---
export async function onRequest(context) {
    const { request } = context;
    if (request.method === "OPTIONS") { return handleOptions(request); }
    // 动态添加来源到允许列表
    const origin = request.headers.get("Origin");
    if (origin && origin.endsWith('.20100505.xyz') && !allowedOrigins.includes(origin)) {
        allowedOrigins.push(origin);
    }
    return handleApiRequest(context);
}

// --- 4. 核心API路由逻辑 ---
async function handleApiRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const pathParts = context.params.path || [];
    const user = getUserFromToken(request);

    try {
        // --- 公共路由 (无需登录) ---
        if (pathParts[0] === 'register'||pathParts[0] === 'login') {
            const { username, password } = await request.json();
            if (!username || !password) return jsonResponse({ error: '用户名和密码不能为空' }, 400, request);
            const password_hash = await hashPassword(password);
            if(pathParts[0] === 'register'){ const existing = await env.DB.prepare("SELECT id FROM Users WHERE username = ?").bind(username).first(); if (existing) return jsonResponse({ error: '用户名已存在' }, 409, request); const count = await env.DB.prepare("SELECT COUNT(id) as c FROM Users").first('c'); await env.DB.prepare("INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)").bind(username, password_hash, (count===0?'admin':'user')).run(); return jsonResponse({ message: '用户注册成功' }, 201, request); }
            if(pathParts[0] === 'login'){ const userDb = await env.DB.prepare("SELECT id, username, role FROM Users WHERE username = ? AND password_hash = ?").bind(username, password_hash).first(); if (!userDb) return jsonResponse({ error: '用户名或密码错误' }, 401, request); const userData = { userId: userDb.id, username: userDb.username, role: userDb.role }; const token = btoa(JSON.stringify(userData)); return jsonResponse({ token, user: userData }, 200, request); }
        }

        if (!user) return jsonResponse({ error: '未授权或Token无效' }, 401, request);

        // --- 导航链接管理 (仅管理员) ---
        if (pathParts[0] === 'navlinks') {
            if (request.method === 'GET') { const { results } = await env.DB.prepare("SELECT id, name, subdomain FROM NavLinks ORDER BY name").all(); return jsonResponse(results, 200, request); }
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') { const { name, subdomain } = await request.json(); const { meta } = await env.DB.prepare("INSERT INTO NavLinks (name, subdomain) VALUES (?, ?)").bind(name, subdomain).run(); return jsonResponse({ id: meta.last_row_id, name, subdomain }, 201, request); }
            if (request.method === 'PUT' && pathParts[1]) { const { name, subdomain } = await request.json(); await env.DB.prepare("UPDATE NavLinks SET name = ?, subdomain = ? WHERE id = ?").bind(name, subdomain, pathParts[1]).run(); return jsonResponse({ message: '更新成功' }, 200, request); }
            if (request.method === 'DELETE' && pathParts[1]) { await env.DB.prepare("DELETE FROM NavLinks WHERE id = ?").bind(pathParts[1]).run(); return jsonResponse(null, 204, request); }
        }

        // --- 小说管理 (仅管理员) ---
        if (pathParts[0] === 'novels') {
            if (request.method === 'GET') { const { results } = await env.DB.prepare("SELECT id, title, author FROM Novels ORDER BY id").all(); return jsonResponse(results, 200, request); }
            if (user.role !== 'admin') return jsonResponse({ error: '无权操作' }, 403, request);
            if (request.method === 'POST') { const { id, title, author } = await request.json(); await env.DB.prepare("INSERT INTO Novels (id, title, author) VALUES (?, ?, ?)").bind(id, title, author).run(); return jsonResponse({ id, title, author }, 201, request); }
            if (request.method === 'PUT' && pathParts[1]) { const { title, author } = await request.json(); await env.DB.prepare("UPDATE Novels SET title = ?, author = ? WHERE id = ?").bind(title, author, pathParts[1]).run(); return jsonResponse({ message: '更新成功' }, 200, request); }
            if (request.method === 'DELETE' && pathParts[1]) { await env.DB.prepare("DELETE FROM Novels WHERE id = ?").bind(pathParts[1]).run(); return jsonResponse(null, 204, request); }
        }
        
        // ★★★ 这里是本次修复的核心：书摘管理 (Snippets) ★★★
        if (pathParts[0] === 'snippets') {
            if (request.method === 'POST') {
                let body;
                try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效请求体 (非JSON)' }, 400, request); }

                const { novel_id, chapter_id, content } = body;
                const userId = user ? user.userId : null;

                if (!userId || !novel_id || !chapter_id || !content) {
                    return jsonResponse({ error: `请求缺少必要字段` }, 400, request);
                }

                try {
                    const stmt = env.DB.prepare("INSERT INTO Snippets (user_id, novel_id, chapter_id, content) VALUES (?1, ?2, ?3, ?4)");
                    const result = await stmt.bind(Number(userId), String(novel_id), String(chapter_id), String(content)).run();
                    
                    if (!result.success) {
                       console.error("D1 Insert Failed:", result.error || "Unknown D1 error");
                       return jsonResponse({ error: '数据库操作失败', details: result.error || 'Unknown' }, 500, request);
                    }
                    return jsonResponse({ id: result.meta.last_row_id, message: '书摘已保存' }, 201, request);
                } catch (dbError) {
                    console.error("数据库插入书摘时发生严重错误:", dbError.message, dbError.cause);
                    return jsonResponse({ error: '数据库后端错误', details: dbError.message }, 500, request);
                }
            }
            if (request.method === 'GET') {
                const novel_id = url.searchParams.get('novel_id'), chapter_id = url.searchParams.get('chapter_id');
                if (!novel_id || !chapter_id) return jsonResponse({ error: "novel_id 和 chapter_id 是必须的" }, 400, request);
                const { results } = await env.DB.prepare("SELECT id, content, created_at FROM Snippets WHERE user_id=? AND novel_id=? AND chapter_id=? ORDER BY created_at DESC").bind(user.userId, novel_id, chapter_id).all();
                return jsonResponse(results, 200, request);
            }
            if (request.method === 'DELETE' && pathParts[1]) { await env.DB.prepare("DELETE FROM Snippets WHERE id = ? AND user_id = ?").bind(pathParts[1], user.userId).run(); return jsonResponse(null, 204, request); }
        }

        // --- 用户阅读进度 ---
        if (pathParts[0] === 'progress' && pathParts[1]) {
            const novel_id = pathParts[1];
            if (request.method === 'POST') {
                const { chapter_id, position } = await request.json();
                await env.DB.prepare(`INSERT INTO ReadingRecords (user_id, novel_id, chapter_id, position) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(user_id, novel_id) DO UPDATE SET chapter_id=?3, position=?4, updated_at=CURRENT_TIMESTAMP`).bind(user.userId, novel_id, chapter_id, position).run();
                return jsonResponse({ message: '进度已保存' }, 200, request);
            }
            if (request.method === 'GET') {
                const record = await env.DB.prepare("SELECT chapter_id, position FROM ReadingRecords WHERE user_id=? AND novel_id=?").bind(user.userId, novel_id).first();
                if (!record) return jsonResponse({}, 404, request);
                return jsonResponse(record, 200, request);
            }
        }

        return jsonResponse({ error: `API路由未找到` }, 404, request);

    } catch (e) {
        console.error("API请求处理时发生未捕获的严重错误:", e.message, e.stack);
        return jsonResponse({ error: '服务器内部发生未知错误', details: e.message }, 500, request);
    }
}

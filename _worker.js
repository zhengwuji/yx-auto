// Cloudflare Worker - 简化版优选工具
// 仅保留优选域名、优选IP、GitHub、上报和节点生成功能

// 默认配置
let customPreferredIPs = [];
let customPreferredDomains = [];
let epd = true;  // 启用优选域名
let epi = true;  // 启用优选IP
let egi = true;  // 启用GitHub优选
let ev = true;   // 启用VLESS协议
let et = false;  // 启用Trojan协议
let vm = false;  // 启用VMess协议
let scu = 'https://url.v1.mk/sub';  // 订阅转换地址

// 密码验证相关函数
function getPassword(env) {
    // 从环境变量获取密码，如果未设置则返回空（表示不需要密码）
    return env?.LOGIN_PASSWORD || '';
}

function generateSessionToken() {
    // 生成简单的会话令牌（实际应用中应使用更安全的方法）
    return btoa(Date.now().toString() + Math.random().toString()).substring(0, 32);
}

// 生成订阅token（永久有效）
// 使用密码的哈希值作为token的基础，确保只有登录用户才能生成有效token
async function generateSubscriptionToken(env) {
    const password = getPassword(env);
    if (!password) {
        // 如果没有设置密码，返回空token（表示不需要验证）
        return '';
    }
    // 使用密码生成一个稳定的token
    // 使用简单的哈希方法（实际应用中可以使用更安全的方法）
    const tokenData = password + 'subscription_token_salt';
    // 生成token（基于密码，确保只有知道密码的人才能生成）
    const hash = await simpleHash(tokenData);
    return hash.substring(0, 48).replace(/[+/=]/g, '');
}

// 简单的哈希函数（用于生成token）
async function simpleHash(str) {
    // 使用Web Crypto API生成哈希
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return btoa(hashHex);
}

// 验证订阅token
async function isValidSubscriptionToken(token, env) {
    const password = getPassword(env);
    if (!password) {
        // 如果没有设置密码，任何token都有效（或不需要token）
        return true;
    }
    if (!token) {
        return false;
    }
    // 重新生成token并比较
    const expectedToken = await generateSubscriptionToken(env);
    return token === expectedToken;
}

function isValidSession(cookieHeader, env) {
    // 检查会话是否有效（简单实现，实际应用中应使用更安全的方法）
    if (!cookieHeader) return false;
    const cookies = Object.fromEntries(
        cookieHeader.split(';').map(c => c.trim().split('='))
    );
    const sessionToken = cookies['cf_session'];
    if (!sessionToken) return false;
    
    // 简单的会话验证（实际应用中应使用 KV 存储或更安全的方法）
    // 这里使用环境变量中的密码作为会话密钥的一部分
    const password = getPassword(env);
    if (!password) return true; // 如果没有设置密码，则允许访问
    
    // 验证会话（简化版，实际应用中应使用更安全的方法）
    try {
        const decoded = atob(sessionToken);
        const timestamp = parseInt(decoded.substring(0, 13));
        const now = Date.now();
        // 会话有效期24小时
        return (now - timestamp) < 24 * 60 * 60 * 1000;
    } catch (e) {
        return false;
    }
}

// 获取客户端IP地址
function getClientIP(request) {
    // 从 Cloudflare 的请求头获取真实IP
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For')?.split(',')[0] || 
           'unknown';
}

// 防暴力破解：检查IP是否被限制
async function checkBruteForceProtection(ip, env) {
    // 如果没有 KV 存储，使用内存缓存（仅限单实例，不推荐生产环境）
    // 建议使用 Cloudflare KV 存储来跨实例共享数据
    
    const MAX_ATTEMPTS = 5; // 最大尝试次数
    const LOCKOUT_TIME = 15 * 60 * 1000; // 锁定时间15分钟
    const ATTEMPT_WINDOW = 60 * 1000; // 尝试窗口1分钟
    
    // 尝试使用 KV 存储
    if (env && env.AUTH_KV) {
        try {
            const kv = env.AUTH_KV;
            const attemptKey = `auth_attempts:${ip}`;
            const lockoutKey = `auth_lockout:${ip}`;
            
            // 检查是否被锁定
            try {
                const lockoutData = await kv.get(lockoutKey);
                if (lockoutData) {
                    const lockoutTime = parseInt(lockoutData);
                    const now = Date.now();
                    if (now < lockoutTime) {
                        const remainingMinutes = Math.ceil((lockoutTime - now) / 60000);
                        return {
                            blocked: true,
                            message: `登录尝试次数过多，请 ${remainingMinutes} 分钟后再试`
                        };
                    } else {
                        // 锁定时间已过，清除锁定
                        try {
                            await kv.delete(lockoutKey);
                            await kv.delete(attemptKey);
                        } catch (e) {
                            // 忽略删除错误
                            console.error('清除锁定记录错误:', e);
                        }
                    }
                }
            } catch (e) {
                console.error('检查锁定状态错误:', e);
            }
            
            // 检查尝试次数
            try {
                const attemptsData = await kv.get(attemptKey);
                if (attemptsData) {
                    const attempts = JSON.parse(attemptsData);
                    const now = Date.now();
                    
                    // 清理过期的尝试记录（超过1分钟）
                    const recentAttempts = attempts.filter(t => now - t < ATTEMPT_WINDOW);
                    
                    if (recentAttempts.length >= MAX_ATTEMPTS) {
                        // 达到最大尝试次数，锁定账户
                        const lockoutUntil = now + LOCKOUT_TIME;
                        try {
                            await kv.put(lockoutKey, lockoutUntil.toString());
                            await kv.delete(attemptKey);
                        } catch (e) {
                            console.error('设置锁定错误:', e);
                        }
                        return {
                            blocked: true,
                            message: `登录尝试次数过多，账户已被锁定 15 分钟`
                        };
                    }
                    
                    // 更新尝试记录
                    recentAttempts.push(now);
                    try {
                        await kv.put(attemptKey, JSON.stringify(recentAttempts), { expirationTtl: Math.ceil(LOCKOUT_TIME / 1000) });
                    } catch (e) {
                        console.error('更新尝试记录错误:', e);
                    }
                }
            } catch (e) {
                console.error('检查尝试次数错误:', e);
            }
            
            return { blocked: false };
        } catch (e) {
            // KV 操作失败，记录错误但不阻止访问
            console.error('KV 操作错误:', e);
            return { blocked: false };
        }
    }
    
    // 如果没有 KV 存储，无法跨实例共享数据，直接返回允许
    // 建议配置 KV 存储以获得完整的防暴力破解保护
    // 注意：Cloudflare Workers 是无状态的，不能使用 global 对象
    return { blocked: false };
}

// 记录失败的登录尝试
async function recordFailedAttempt(ip, env) {
    if (env && env.AUTH_KV) {
        try {
            const kv = env.AUTH_KV;
            const attemptKey = `auth_attempts:${ip}`;
            const attemptsData = await kv.get(attemptKey);
            const attempts = attemptsData ? JSON.parse(attemptsData) : [];
            attempts.push(Date.now());
            await kv.put(attemptKey, JSON.stringify(attempts), { expirationTtl: 900 }); // 15分钟过期
        } catch (e) {
            // 忽略记录失败的错误，不影响登录流程
            console.error('记录失败尝试错误:', e);
        }
    }
    // 如果没有 KV 存储，无法记录尝试次数
    // 建议配置 KV 存储以获得完整的防暴力破解保护
}

// 清除成功的登录尝试记录
async function clearFailedAttempts(ip, env) {
    if (env && env.AUTH_KV) {
        try {
            const kv = env.AUTH_KV;
            await kv.delete(`auth_attempts:${ip}`);
            await kv.delete(`auth_lockout:${ip}`);
        } catch (e) {
            // 忽略清除失败的错误
            console.error('清除失败尝试记录错误:', e);
        }
    }
    // 如果没有 KV 存储，无需清除
}

// 订阅统计相关函数
// 记录订阅访问
async function recordSubscriptionAccess(request, uuid, env) {
    const clientIP = getClientIP(request);
    const timestamp = Date.now();
    
    try {
        // 使用 KV 存储（如果可用）
        if (env && env.AUTH_KV) {
            const kv = env.AUTH_KV;
            
            // 记录总访问次数
            const totalKey = 'sub_stats:total';
            const totalData = await kv.get(totalKey);
            const totalCount = totalData ? parseInt(totalData) : 0;
            await kv.put(totalKey, (totalCount + 1).toString(), { expirationTtl: 2592000 }); // 30天过期
            
            // 记录唯一订阅链接（通过UUID识别）
            const uniqueKey = `sub_unique:${uuid}`;
            const uniqueExists = await kv.get(uniqueKey);
            if (!uniqueExists) {
                // 这是一个新的订阅链接
                const generatedKey = 'sub_stats:generated';
                const generatedData = await kv.get(generatedKey);
                const generatedCount = generatedData ? parseInt(generatedData) : 0;
                await kv.put(generatedKey, (generatedCount + 1).toString(), { expirationTtl: 2592000 });
                await kv.put(uniqueKey, '1', { expirationTtl: 2592000 }); // 标记已生成
            }
            
            // 记录IP访问（24小时内只记录一次）
            const ipKey = `sub_ip:${clientIP}`;
            const ipData = await kv.get(ipKey);
            if (!ipData) {
                // 记录新的IP访问
                const ipListKey = 'sub_stats:ip_list';
                const ipListData = await kv.get(ipListKey);
                let ipList = ipListData ? JSON.parse(ipListData) : [];
                
                // 移除超过7天的记录
                const sevenDaysAgo = timestamp - 7 * 24 * 60 * 60 * 1000;
                ipList = ipList.filter(item => item.timestamp > sevenDaysAgo);
                
                // 添加新IP
                ipList.push({
                    ip: clientIP,
                    timestamp: timestamp,
                    uuid: uuid
                });
                
                await kv.put(ipListKey, JSON.stringify(ipList), { expirationTtl: 604800 }); // 7天过期
                await kv.put(ipKey, timestamp.toString(), { expirationTtl: 86400 }); // 24小时内不重复记录
            }
            
            // 记录当前活跃订阅（24小时内的访问）
            const activeKey = `sub_active:${uuid}`;
            await kv.put(activeKey, timestamp.toString(), { expirationTtl: 86400 });
        }
    } catch (e) {
        // 忽略统计记录错误，不影响订阅功能
        console.error('记录订阅访问错误:', e);
    }
}

// 获取订阅统计
async function getSubscriptionStats(env) {
    try {
        if (env && env.AUTH_KV) {
            const kv = env.AUTH_KV;
            
            // 获取总访问次数
            const totalKey = 'sub_stats:total';
            const totalData = await kv.get(totalKey);
            const totalCount = totalData ? parseInt(totalData) : 0;
            
            // 获取生成的订阅数
            const generatedKey = 'sub_stats:generated';
            const generatedData = await kv.get(generatedKey);
            const generatedCount = generatedData ? parseInt(generatedData) : 0;
            
            // 获取IP列表
            const ipListKey = 'sub_stats:ip_list';
            const ipListData = await kv.get(ipListKey);
            let ipList = ipListData ? JSON.parse(ipListData) : [];
            
            // 清理过期IP（超过7天）
            const now = Date.now();
            const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
            const originalLength = ipList.length;
            ipList = ipList.filter(item => item.timestamp > sevenDaysAgo);
            
            // 如果有清理，保存回KV（优化存储）
            if (ipList.length < originalLength) {
                await kv.put(ipListKey, JSON.stringify(ipList), { expirationTtl: 604800 });
            }
            
            // 获取唯一IP列表（去重，只统计24小时内的活跃IP）
            const oneDayAgo = now - 24 * 60 * 60 * 1000;
            const recentIPs = ipList.filter(item => item.timestamp > oneDayAgo);
            const uniqueIPs = [...new Set(recentIPs.map(item => item.ip))];
            
            // 所有唯一IP（7天内）
            const allUniqueIPs = [...new Set(ipList.map(item => item.ip))];
            
            return {
                totalAccess: totalCount,
                generatedCount: generatedCount,
                activeCount: uniqueIPs.length, // 24小时内的活跃订阅者数
                ipList: allUniqueIPs.slice(0, 50), // 最多返回50个IP（7天内所有）
                allIPs: allUniqueIPs.length // 7天内所有唯一IP数
            };
        }
        
        // 如果没有 KV 存储，返回默认值
        return {
            totalAccess: 0,
            generatedCount: 0,
            activeCount: 0,
            ipList: [],
            allIPs: 0
        };
    } catch (e) {
        console.error('获取订阅统计错误:', e);
        return {
            totalAccess: 0,
            generatedCount: 0,
            activeCount: 0,
            ipList: [],
            allIPs: 0
        };
    }
}

function generateLoginPage(error = '') {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>登录 - 服务器优选工具</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(180deg, #f5f5f7 0%, #ffffff 100%);
            color: #1d1d1f;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            max-width: 400px;
            width: 100%;
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border-radius: 20px;
            padding: 40px 30px;
            box-shadow: 0 2px 16px rgba(0, 0, 0, 0.08);
            border: 0.5px solid rgba(0, 0, 0, 0.04);
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: #1d1d1f;
            margin-bottom: 8px;
        }
        
        .login-header p {
            font-size: 15px;
            color: #86868b;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #86868b;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            background: rgba(142, 142, 147, 0.12);
            border: none;
            border-radius: 12px;
            outline: none;
            transition: all 0.2s ease;
            -webkit-appearance: none;
        }
        
        .form-group input:focus {
            background: rgba(142, 142, 147, 0.16);
        }
        
        .error-message {
            background: rgba(255, 59, 48, 0.1);
            color: #ff3b30;
            padding: 12px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 20px;
            display: ${error ? 'block' : 'none'};
            word-break: break-word;
        }
        
        .warning-message {
            background: rgba(255, 149, 0, 0.1);
            color: #ff9500;
            padding: 12px;
            border-radius: 8px;
            font-size: 13px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .btn {
            width: 100%;
            padding: 16px;
            font-size: 17px;
            font-weight: 600;
            color: #ffffff;
            background: #007aff;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-appearance: none;
            box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
        }
        
        .btn:active {
            transform: scale(0.98);
            opacity: 0.8;
        }
        
        .info-text {
            margin-top: 20px;
            padding: 12px;
            background: rgba(142, 142, 147, 0.12);
            border-radius: 8px;
            font-size: 13px;
            color: #86868b;
            text-align: center;
        }
        
        @media (prefers-color-scheme: dark) {
            body {
                background: linear-gradient(180deg, #000000 0%, #1c1c1e 100%);
                color: #f5f5f7;
            }
            
            .login-container {
                background: rgba(28, 28, 30, 0.8);
                border: 0.5px solid rgba(255, 255, 255, 0.1);
            }
            
            .form-group input {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            .form-group input:focus {
                background: rgba(142, 142, 147, 0.25);
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>服务器优选工具</h1>
            <p>请输入登录密码</p>
        </div>
        
        <div class="error-message" id="errorMsg">${error}</div>
        
        <div class="warning-message">
            <p>⚠️ 安全提示：连续 5 次登录失败将被锁定 15 分钟</p>
        </div>
        
        <form method="POST" action="/login" id="loginForm">
            <div class="form-group">
                <label>密码</label>
                <input type="password" name="password" id="password" placeholder="请输入密码" required autofocus>
            </div>
            
            <button type="submit" class="btn">登录</button>
        </form>
        
        <div class="info-text">
            <p>忘记密码？请联系管理员在 Cloudflare Workers 后台重置</p>
            <p style="margin-top: 8px; font-size: 12px;">订阅链接需要登录后才能访问</p>
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const password = document.getElementById('password').value;
            if (!password) {
                document.getElementById('errorMsg').textContent = '请输入密码';
                document.getElementById('errorMsg').style.display = 'block';
                return;
            }
            this.submit();
        });
    </script>
</body>
</html>`;
}

// 默认优选域名列表
const directDomains = [
    { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" },
    { domain: "freeyx.cloudflare88.eu.org" },
    { domain: "bestcf.top" },
    { domain: "cdn.2020111.xyz" },
    { domain: "cf.0sm.com" },
    { domain: "cf.090227.xyz" },
    { domain: "cf.zhetengsha.eu.org" },
    { domain: "cfip.1323123.xyz" },
    { domain: "cloudflare-ip.mofashi.ltd" },
    { domain: "cf.877771.xyz" },
    { domain: "xn--b6gac.eu.org" }
];

// 默认优选IP来源URL
const defaultIPURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';

// UUID验证
function isValidUUID(str) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(str);
}

// 从环境变量获取配置
function getConfigValue(key, defaultValue) {
    return defaultValue || '';
}

// 获取动态IP列表（支持IPv4/IPv6和运营商筛选）
async function fetchDynamicIPs(ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
    const v4Url = "https://www.wetest.vip/page/cloudflare/address_v4.html";
    const v6Url = "https://www.wetest.vip/page/cloudflare/address_v6.html";
    let results = [];

    try {
        const fetchPromises = [];
        if (ipv4Enabled) {
            fetchPromises.push(fetchAndParseWetest(v4Url));
        } else {
            fetchPromises.push(Promise.resolve([]));
        }
        if (ipv6Enabled) {
            fetchPromises.push(fetchAndParseWetest(v6Url));
        } else {
            fetchPromises.push(Promise.resolve([]));
        }

        const [ipv4List, ipv6List] = await Promise.all(fetchPromises);
        results = [...ipv4List, ...ipv6List];
        
        // 按运营商筛选
        if (results.length > 0) {
            results = results.filter(item => {
                const isp = item.isp || '';
                if (isp.includes('移动') && !ispMobile) return false;
                if (isp.includes('联通') && !ispUnicom) return false;
                if (isp.includes('电信') && !ispTelecom) return false;
                return true;
            });
        }
        
        return results.length > 0 ? results : [];
    } catch (e) {
        return [];
    }
}

// 解析wetest页面
async function fetchAndParseWetest(url) {
    try {
        const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) return [];
        const html = await response.text();
        const results = [];
        const rowRegex = /<tr[\s\S]*?<\/tr>/g;
        const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>[\s\S]*?<td data-label="数据中心">(.+?)<\/td>/;

        let match;
        while ((match = rowRegex.exec(html)) !== null) {
            const rowHtml = match[0];
            const cellMatch = rowHtml.match(cellRegex);
            if (cellMatch && cellMatch[1] && cellMatch[2]) {
                const colo = cellMatch[3] ? cellMatch[3].trim().replace(/<.*?>/g, '') : '';
                results.push({
                    isp: cellMatch[1].trim().replace(/<.*?>/g, ''),
                    ip: cellMatch[2].trim(),
                    colo: colo
                });
            }
        }
        return results;
    } catch (error) {
        return [];
    }
}

// 从GitHub获取优选IP
async function fetchAndParseNewIPs(piu) {
    const url = piu || defaultIPURL;
    try {
        const response = await fetch(url);
        if (!response.ok) return [];
        const text = await response.text();
        const results = [];
        const lines = text.trim().replace(/\r/g, "").split('\n');
        const regex = /^([^:]+):(\d+)#(.*)$/;

        for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine) continue;
            const match = trimmedLine.match(regex);
            if (match) {
                results.push({
                    ip: match[1],
                    port: parseInt(match[2], 10),
                    name: match[3].trim() || match[1]
                });
            }
        }
        return results;
    } catch (error) {
        return [];
    }
}

// 从自定义URL获取优选IP（yxURL功能）
async function fetchPreferredIPsFromURL(yxURL, ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
    if (!yxURL) {
        return [];
    }
    
    try {
        const response = await fetch(yxURL, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) return [];
        
        const contentType = response.headers.get('content-type') || '';
        let results = [];
        
        // 判断是HTML页面还是文本文件
        if (contentType.includes('text/html')) {
            // HTML格式，使用wetest解析方式
            const html = await response.text();
            const rowRegex = /<tr[\s\S]*?<\/tr>/g;
            const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>[\s\S]*?<td data-label="数据中心">(.+?)<\/td>/;
            
            let match;
            while ((match = rowRegex.exec(html)) !== null) {
                const rowHtml = match[0];
                const cellMatch = rowHtml.match(cellRegex);
                if (cellMatch && cellMatch[1] && cellMatch[2]) {
                    const colo = cellMatch[3] ? cellMatch[3].trim().replace(/<.*?>/g, '') : '';
                    const ip = cellMatch[2].trim();
                    // 检查IP版本
                    const isIPv6 = ip.includes(':');
                    if ((isIPv6 && !ipv6Enabled) || (!isIPv6 && !ipv4Enabled)) {
                        continue;
                    }
                    results.push({
                        isp: cellMatch[1].trim().replace(/<.*?>/g, ''),
                        ip: ip,
                        colo: colo
                    });
                }
            }
        } else {
            // 文本格式，使用GitHub格式解析
            const text = await response.text();
            const lines = text.trim().replace(/\r/g, "").split('\n');
            const regex = /^([^:]+):(\d+)#(.*)$/;
            
            for (const line of lines) {
                const trimmedLine = line.trim();
                if (!trimmedLine) continue;
                const match = trimmedLine.match(regex);
                if (match) {
                    const ip = match[1];
                    const isIPv6 = ip.includes(':');
                    if ((isIPv6 && !ipv6Enabled) || (!isIPv6 && !ipv4Enabled)) {
                        continue;
                    }
                    results.push({
                        ip: ip,
                        port: parseInt(match[2], 10),
                        name: match[3].trim() || ip,
                        isp: match[3].trim() || ip
                    });
                }
            }
        }
        
        // 按运营商筛选
        if (results.length > 0) {
            results = results.filter(item => {
                const isp = item.isp || '';
                if (isp.includes('移动') && !ispMobile) return false;
                if (isp.includes('联通') && !ispUnicom) return false;
                if (isp.includes('电信') && !ispTelecom) return false;
                return true;
            });
        }
        
        return results;
    } catch (error) {
        console.error('从自定义URL获取优选IP失败:', error);
        return [];
    }
}

// 生成VLESS链接
function generateLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/') {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const defaultHttpsPorts = [443];
    const defaultHttpPorts = disableNonTLS ? [] : [80];
    const links = [];
    const wsPath = customPath || '/';
    const proto = 'vless';

    list.forEach(item => {
        let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
        if (item.colo && item.colo.trim()) {
            nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
        }
        const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
        
        let portsToGenerate = [];
        
        if (item.port) {
            const port = item.port;
            if (CF_HTTPS_PORTS.includes(port)) {
                portsToGenerate.push({ port: port, tls: true });
            } else if (CF_HTTP_PORTS.includes(port)) {
                portsToGenerate.push({ port: port, tls: false });
            } else {
                portsToGenerate.push({ port: port, tls: true });
            }
        } else {
            defaultHttpsPorts.forEach(port => {
                portsToGenerate.push({ port: port, tls: true });
            });
            defaultHttpPorts.forEach(port => {
                portsToGenerate.push({ port: port, tls: false });
            });
        }

        portsToGenerate.forEach(({ port, tls }) => {
            if (tls) {
                const wsNodeName = `${nodeNameBase}-${port}-WS-TLS`;
                const wsParams = new URLSearchParams({ 
                    encryption: 'none', 
                    security: 'tls', 
                    sni: workerDomain, 
                    fp: 'chrome', 
                    alpn: 'h2,http/1.1',
                    type: 'ws', 
                    host: workerDomain, 
                    path: wsPath
                });
                links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
            } else {
                const wsNodeName = `${nodeNameBase}-${port}-WS`;
                const wsParams = new URLSearchParams({
                    encryption: 'none',
                    security: 'none',
                    type: 'ws',
                    host: workerDomain,
                    path: wsPath
                });
                links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
            }
        });
    });
    return links;
}

// 生成Trojan链接
async function generateTrojanLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/') {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const defaultHttpsPorts = [443];
    const defaultHttpPorts = disableNonTLS ? [] : [80];
    const links = [];
    const wsPath = customPath || '/';
    const password = user;  // Trojan使用UUID作为密码

    list.forEach(item => {
        let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
        if (item.colo && item.colo.trim()) {
            nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
        }
        const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
        
        let portsToGenerate = [];
        
        if (item.port) {
            const port = item.port;
            if (CF_HTTPS_PORTS.includes(port)) {
                portsToGenerate.push({ port: port, tls: true });
            } else if (CF_HTTP_PORTS.includes(port)) {
                if (!disableNonTLS) {
                    portsToGenerate.push({ port: port, tls: false });
                }
            } else {
                portsToGenerate.push({ port: port, tls: true });
            }
        } else {
            defaultHttpsPorts.forEach(port => {
                portsToGenerate.push({ port: port, tls: true });
            });
            defaultHttpPorts.forEach(port => {
                portsToGenerate.push({ port: port, tls: false });
            });
        }

        portsToGenerate.forEach(({ port, tls }) => {
            if (tls) {
                const wsNodeName = `${nodeNameBase}-${port}-Trojan-WS-TLS`;
                const wsParams = new URLSearchParams({ 
                    security: 'tls', 
                    sni: workerDomain, 
                    fp: 'chrome', 
                    alpn: 'h2,http/1.1',
                    type: 'ws', 
                    host: workerDomain, 
                    path: wsPath
                });
                links.push(`trojan://${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
            } else {
                const wsNodeName = `${nodeNameBase}-${port}-Trojan-WS`;
                const wsParams = new URLSearchParams({
                    security: 'none',
                    type: 'ws',
                    host: workerDomain,
                    path: wsPath
                });
                links.push(`trojan://${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
            }
        });
    });
    return links;
}

// 生成VMess链接
function generateVMessLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/') {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const defaultHttpsPorts = [443];
    const defaultHttpPorts = disableNonTLS ? [] : [80];
    const links = [];
    const wsPath = customPath || '/';

    list.forEach(item => {
        let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
        if (item.colo && item.colo.trim()) {
            nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
        }
        const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
        
        let portsToGenerate = [];
        
        if (item.port) {
            const port = item.port;
            if (CF_HTTPS_PORTS.includes(port)) {
                portsToGenerate.push({ port: port, tls: true });
            } else if (CF_HTTP_PORTS.includes(port)) {
                if (!disableNonTLS) {
                    portsToGenerate.push({ port: port, tls: false });
                }
            } else {
                portsToGenerate.push({ port: port, tls: true });
            }
        } else {
            defaultHttpsPorts.forEach(port => {
                portsToGenerate.push({ port: port, tls: true });
            });
            defaultHttpPorts.forEach(port => {
                portsToGenerate.push({ port: port, tls: false });
            });
        }

        portsToGenerate.forEach(({ port, tls }) => {
            const vmessConfig = {
                v: "2",
                ps: tls ? `${nodeNameBase}-${port}-VMess-WS-TLS` : `${nodeNameBase}-${port}-VMess-WS`,
                add: safeIP,
                port: port.toString(),
                id: user,
                aid: "0",
                scy: "auto",
                net: "ws",
                type: "none",
                host: workerDomain,
                path: wsPath,
                tls: tls ? "tls" : "none"
            };
            if (tls) {
                vmessConfig.sni = workerDomain;
                vmessConfig.fp = "chrome";
                vmessConfig.alpn = "h2,http/1.1";
            }
            const vmessBase64 = btoa(JSON.stringify(vmessConfig));
            links.push(`vmess://${vmessBase64}`);
        });
    });
    return links;
}

// 从GitHub IP生成链接（VLESS）
function generateLinksFromNewIPs(list, user, workerDomain, customPath = '/') {
    const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
    const links = [];
    const wsPath = customPath || '/';
    const proto = 'vless';
    
    list.forEach(item => {
        const nodeName = item.name.replace(/\s/g, '_');
        const port = item.port;
        
        if (CF_HTTPS_PORTS.includes(port)) {
            const wsNodeName = `${nodeName}-${port}-WS-TLS`;
            const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&alpn=h2,http/1.1&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
            links.push(link);
        } else if (CF_HTTP_PORTS.includes(port)) {
            const wsNodeName = `${nodeName}-${port}-WS`;
            const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
            links.push(link);
        } else {
            const wsNodeName = `${nodeName}-${port}-WS-TLS`;
            const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&alpn=h2,http/1.1&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
            links.push(link);
        }
    });
    return links;
}

// 生成订阅内容
async function handleSubscriptionRequest(request, user, customDomain, piu, yxURL, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, env) {
    const url = new URL(request.url);
    const finalLinks = [];
    const workerDomain = url.hostname;  // workerDomain始终是请求的hostname
    const nodeDomain = customDomain || url.hostname;  // 用户输入的域名用于生成节点时的host/sni
    const target = url.searchParams.get('target') || 'base64';
    const wsPath = customPath || '/';

    async function addNodesFromList(list) {
        // 确保至少有一个协议被启用
        const hasProtocol = evEnabled || etEnabled || vmEnabled;
        const useVL = hasProtocol ? evEnabled : true;  // 如果没有选择任何协议，默认使用VLESS
        
        if (useVL) {
            finalLinks.push(...generateLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath));
        }
        if (etEnabled) {
            finalLinks.push(...await generateTrojanLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath));
        }
        if (vmEnabled) {
            finalLinks.push(...generateVMessLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath));
        }
    }

    // 原生地址
    const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
    await addNodesFromList(nativeList);

    // 优选域名
    if (epd) {
        const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
        await addNodesFromList(domainList);
    }

    // 优选IP（如果设置了自定义yxURL，优先使用自定义URL，否则使用默认wetest）
    if (epi) {
        if (yxURL) {
            // 使用自定义yxURL
            try {
                const customIPList = await fetchPreferredIPsFromURL(yxURL, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
                if (customIPList.length > 0) {
                    await addNodesFromList(customIPList);
                }
            } catch (error) {
                console.error('从自定义URL获取优选IP失败:', error);
                // 如果自定义URL失败，回退到默认wetest
                try {
                    const dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
                    if (dynamicIPList.length > 0) {
                        await addNodesFromList(dynamicIPList);
                    }
                } catch (e) {
                    console.error('获取动态IP失败:', e);
                }
            }
        } else {
            // 使用默认wetest
            try {
                const dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
                if (dynamicIPList.length > 0) {
                    await addNodesFromList(dynamicIPList);
                }
            } catch (error) {
                console.error('获取动态IP失败:', error);
            }
        }
    }

    // GitHub优选
    if (egi) {
        try {
            const newIPList = await fetchAndParseNewIPs(piu);
            if (newIPList.length > 0) {
                // 确保至少有一个协议被启用
                const hasProtocol = evEnabled || etEnabled || vmEnabled;
                const useVL = hasProtocol ? evEnabled : true;  // 如果没有选择任何协议，默认使用VLESS
                
                if (useVL) {
                    finalLinks.push(...generateLinksFromNewIPs(newIPList, user, nodeDomain, wsPath));
                }
                // GitHub IP只支持VLESS格式
            }
        } catch (error) {
            console.error('获取GitHub IP失败:', error);
        }
    }

    if (finalLinks.length === 0) {
        const errorRemark = "所有节点获取失败";
        const errorLink = `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent(errorRemark)}`;
        finalLinks.push(errorLink);
    }

    let subscriptionContent;
    let contentType = 'text/plain; charset=utf-8';
    
    switch (target.toLowerCase()) {
        case 'clash':
        case 'clashr':
            subscriptionContent = generateClashConfig(finalLinks);
            contentType = 'text/yaml; charset=utf-8';
            break;
        case 'surge':
        case 'surge2':
        case 'surge3':
        case 'surge4':
            subscriptionContent = generateSurgeConfig(finalLinks);
            break;
        case 'quantumult':
        case 'quanx':
            subscriptionContent = generateQuantumultConfig(finalLinks);
            break;
        default:
            subscriptionContent = btoa(finalLinks.join('\n'));
    }
    
    // 记录订阅访问（异步，不阻塞响应）
    if (env) {
        recordSubscriptionAccess(request, user, env).catch(e => {
            // 忽略记录错误，不影响订阅功能
            console.error('记录订阅访问失败:', e);
        });
    }
    
    return new Response(subscriptionContent, {
        headers: { 
            'Content-Type': contentType,
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        },
    });
}

// 生成Clash配置（简化版，返回YAML格式）
function generateClashConfig(links) {
    let yaml = 'port: 7890\n';
    yaml += 'socks-port: 7891\n';
    yaml += 'allow-lan: false\n';
    yaml += 'mode: rule\n';
    yaml += 'log-level: info\n\n';
    yaml += 'proxies:\n';
    
    const proxyNames = [];
    links.forEach((link, index) => {
        const name = decodeURIComponent(link.split('#')[1] || `节点${index + 1}`);
        proxyNames.push(name);
        const server = link.match(/@([^:]+):(\d+)/)?.[1] || '';
        const port = link.match(/@[^:]+:(\d+)/)?.[1] || '443';
        const uuid = link.match(/vless:\/\/([^@]+)@/)?.[1] || '';
        const tls = link.includes('security=tls');
        const path = link.match(/path=([^&#]+)/)?.[1] || '/';
        const host = link.match(/host=([^&#]+)/)?.[1] || '';
        const sni = link.match(/sni=([^&#]+)/)?.[1] || '';
        
        yaml += `  - name: ${name}\n`;
        yaml += `    type: vless\n`;
        yaml += `    server: ${server}\n`;
        yaml += `    port: ${port}\n`;
        yaml += `    uuid: ${uuid}\n`;
        yaml += `    tls: ${tls}\n`;
        yaml += `    network: ws\n`;
        yaml += `    ws-opts:\n`;
        yaml += `      path: ${path}\n`;
        yaml += `      headers:\n`;
        yaml += `        Host: ${host}\n`;
        if (sni) {
            yaml += `    servername: ${sni}\n`;
        }
    });
    
    yaml += '\nproxy-groups:\n';
    yaml += '  - name: PROXY\n';
    yaml += '    type: select\n';
    yaml += `    proxies: [${proxyNames.map(n => `'${n}'`).join(', ')}]\n`;
    yaml += '\nrules:\n';
    yaml += '  - DOMAIN-SUFFIX,local,DIRECT\n';
    yaml += '  - IP-CIDR,127.0.0.0/8,DIRECT\n';
    yaml += '  - GEOIP,CN,DIRECT\n';
    yaml += '  - MATCH,PROXY\n';
    
    return yaml;
}

// 生成Surge配置
function generateSurgeConfig(links) {
    let config = '[Proxy]\n';
    links.forEach(link => {
        const name = decodeURIComponent(link.split('#')[1] || '节点');
        config += `${name} = vless, ${link.match(/@([^:]+):(\d+)/)?.[1] || ''}, ${link.match(/@[^:]+:(\d+)/)?.[1] || '443'}, username=${link.match(/vless:\/\/([^@]+)@/)?.[1] || ''}, tls=${link.includes('security=tls')}, ws=true, ws-path=${link.match(/path=([^&#]+)/)?.[1] || '/'}, ws-headers=Host:${link.match(/host=([^&#]+)/)?.[1] || ''}\n`;
    });
    config += '\n[Proxy Group]\nPROXY = select, ' + links.map((_, i) => decodeURIComponent(links[i].split('#')[1] || `节点${i + 1}`)).join(', ') + '\n';
    return config;
}

// 生成Quantumult配置
function generateQuantumultConfig(links) {
    return btoa(links.join('\n'));
}

// 生成iOS 26风格的主页
async function generateHomePage(scuValue, env) {
    const scu = scuValue || 'https://url.v1.mk/sub';
    // 生成订阅token（永久有效）
    const subscriptionToken = await generateSubscriptionToken(env);
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>服务器优选工具</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(180deg, #f5f5f7 0%, #ffffff 100%);
            color: #1d1d1f;
            min-height: 100vh;
            padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
            overflow-x: hidden;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 40px 20px 30px;
        }
        
        .header h1 {
            font-size: 34px;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: #1d1d1f;
            margin-bottom: 8px;
        }
        
        .header p {
            font-size: 17px;
            color: #86868b;
            font-weight: 400;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 2px 16px rgba(0, 0, 0, 0.08);
            border: 0.5px solid rgba(0, 0, 0, 0.04);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #86868b;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            background: rgba(142, 142, 147, 0.12);
            border: none;
            border-radius: 12px;
            outline: none;
            transition: all 0.2s ease;
            -webkit-appearance: none;
        }
        
        .form-group input:focus {
            background: rgba(142, 142, 147, 0.16);
            transform: scale(1.01);
        }
        
        .form-group input::placeholder {
            color: #86868b;
        }
        
        .switch-group {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 0;
        }
        
        .switch-group label {
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            text-transform: none;
            letter-spacing: 0;
        }
        
        .switch {
            position: relative;
            width: 51px;
            height: 31px;
            background: rgba(142, 142, 147, 0.3);
            border-radius: 16px;
            transition: background 0.3s ease;
            cursor: pointer;
        }
        
        .switch.active {
            background: #34c759;
        }
        
        .switch::after {
            content: '';
            position: absolute;
            top: 2px;
            left: 2px;
            width: 27px;
            height: 27px;
            background: #ffffff;
            border-radius: 50%;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .switch.active::after {
            transform: translateX(20px);
        }
        
        .btn {
            width: 100%;
            padding: 16px;
            font-size: 17px;
            font-weight: 600;
            color: #ffffff;
            background: #007aff;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-top: 8px;
            -webkit-appearance: none;
            box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
        }
        
        .btn:active {
            transform: scale(0.98);
            opacity: 0.8;
        }
        
        .btn-secondary {
            background: rgba(142, 142, 147, 0.12);
            color: #007aff;
            box-shadow: none;
        }
        
        .btn-secondary:active {
            background: rgba(142, 142, 147, 0.2);
        }
        
        .result {
            margin-top: 20px;
            padding: 16px;
            background: rgba(142, 142, 147, 0.12);
            border-radius: 12px;
            font-size: 15px;
            color: #1d1d1f;
            word-break: break-all;
            display: none;
        }
        
        .result.show {
            display: block;
        }
        
        .result-url {
            margin-top: 12px;
            padding: 12px;
            background: rgba(0, 122, 255, 0.1);
            border-radius: 8px;
            font-size: 13px;
            color: #007aff;
            word-break: break-all;
        }
        
        .copy-btn {
            margin-top: 8px;
            padding: 10px 16px;
            font-size: 15px;
            background: rgba(0, 122, 255, 0.1);
            color: #007aff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
        }
        
        .client-btn {
            padding: 12px 10px;
            font-size: 14px;
            font-weight: 500;
            color: #007aff;
            background: rgba(0, 122, 255, 0.1);
            border: 1px solid rgba(0, 122, 255, 0.2);
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-appearance: none;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            min-width: 0;
        }
        
        .client-btn:active {
            transform: scale(0.98);
            background: rgba(0, 122, 255, 0.2);
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 17px;
            font-weight: 400;
            user-select: none;
            -webkit-user-select: none;
            position: relative;
            z-index: 1;
        }
        
        .checkbox-label input[type="checkbox"] {
            margin-right: 8px;
            width: 20px;
            height: 20px;
            cursor: pointer;
            flex-shrink: 0;
            position: relative;
            z-index: 2;
            -webkit-appearance: checkbox;
            appearance: checkbox;
        }
        
        .checkbox-label span {
            cursor: pointer;
            position: relative;
            z-index: 1;
        }
        
        @media (max-width: 480px) {
            .client-btn {
                font-size: 12px;
                padding: 10px 8px;
            }
        }
        
        .footer {
            text-align: center;
            padding: 30px 20px;
            color: #86868b;
            font-size: 13px;
        }
        
        .footer a {
            transition: opacity 0.2s ease;
        }
        
        .footer a:active {
            opacity: 0.6;
        }
        
        .stats-card {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 2px 16px rgba(0, 0, 0, 0.08);
            border: 0.5px solid rgba(0, 0, 0, 0.04);
        }
        
        .stats-title {
            font-size: 17px;
            font-weight: 600;
            color: #1d1d1f;
            margin-bottom: 16px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .stat-item {
            text-align: center;
            padding: 12px 8px;
            background: rgba(142, 142, 147, 0.12);
            border-radius: 12px;
        }
        
        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: #007aff;
            display: block;
            margin-bottom: 4px;
        }
        
        .stat-label {
            font-size: 12px;
            color: #86868b;
        }
        
        .ip-select {
            width: 100%;
            padding: 14px 16px;
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            background: rgba(142, 142, 147, 0.12);
            border: none;
            border-radius: 12px;
            outline: none;
            transition: all 0.2s ease;
            -webkit-appearance: none;
            appearance: none;
            cursor: pointer;
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%231d1d1f' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-position: right 12px center;
            background-size: 20px;
            padding-right: 40px;
        }
        
        .ip-select:focus {
            background: rgba(142, 142, 147, 0.16);
            transform: scale(1.01);
        }
        
        .ip-select option {
            padding: 10px;
            background: #ffffff;
            color: #1d1d1f;
        }
        
        .loading {
            text-align: center;
            color: #86868b;
            padding: 20px;
        }
        
        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: repeat(3, 1fr);
                gap: 8px;
            }
            
            .stat-value {
                font-size: 20px;
            }
            
            .stat-label {
                font-size: 11px;
            }
        }
        
        @media (prefers-color-scheme: dark) {
            body {
                background: linear-gradient(180deg, #000000 0%, #1c1c1e 100%);
                color: #f5f5f7;
            }
            
            .card {
                background: rgba(28, 28, 30, 0.8);
                border: 0.5px solid rgba(255, 255, 255, 0.1);
            }
            
            .form-group input {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            .form-group input:focus {
                background: rgba(142, 142, 147, 0.25);
            }
            
            .switch-group label {
                color: #f5f5f7;
            }
            
            .result {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            select {
                background: rgba(142, 142, 147, 0.2) !important;
                color: #f5f5f7 !important;
            }
            
            label span {
                color: #f5f5f7;
            }
            
            .client-btn {
                background: rgba(0, 122, 255, 0.15) !important;
                border-color: rgba(0, 122, 255, 0.3) !important;
                color: #5ac8fa !important;
            }
            
            .footer a {
                color: #5ac8fa !important;
            }
            
            .stats-card {
                background: rgba(28, 28, 30, 0.8);
                border: 0.5px solid rgba(255, 255, 255, 0.1);
            }
            
            .stats-title {
                color: #f5f5f7;
            }
            
            .stat-item {
                background: rgba(142, 142, 147, 0.2);
            }
            
            .stat-value {
                color: #5ac8fa;
            }
            
            .ip-select {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
                background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23f5f5f7' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
            }
            
            .ip-select:focus {
                background: rgba(142, 142, 147, 0.25);
            }
            
            .ip-select option {
                background: #1c1c1e;
                color: #f5f5f7;
            }
            
            .loading {
                color: #86868b;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>服务器优选工具</h1>
            <p>智能优选 • 一键生成</p>
        </div>
        
        <div class="stats-card" id="statsCard">
            <div class="stats-title">📊 订阅统计</div>
            <div class="loading" id="statsLoading">加载中...</div>
            <div id="statsContent" style="display: none;">
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-value" id="statActive">0</span>
                        <span class="stat-label">当前使用</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value" id="statGenerated">0</span>
                        <span class="stat-label">已生成</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value" id="statTotal">0</span>
                        <span class="stat-label">总访问</span>
                    </div>
                </div>
                <div class="form-group" style="margin-top: 12px; margin-bottom: 0;">
                    <label>订阅者IP列表（共 <span id="ipCount">0</span> 个）</label>
                    <select class="ip-select" id="ipList" disabled>
                        <option value="">加载中...</option>
                    </select>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="form-group">
                <label>域名</label>
                <input type="text" id="domain" placeholder="请输入您的域名">
            </div>
            
            <div class="form-group">
                <label>UUID</label>
                <input type="text" id="uuid" placeholder="请输入UUID">
            </div>
            
            <div class="form-group">
                <label>WebSocket路径（可选）</label>
                <input type="text" id="customPath" placeholder="留空则使用默认路径 /" value="/">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">自定义WebSocket路径，例如：/v2ray 或 /</small>
            </div>
            
            <div class="switch-group">
                <label>启用优选域名</label>
                <div class="switch active" id="switchDomain" onclick="toggleSwitch('switchDomain')"></div>
            </div>
            
            <div class="switch-group">
                <label>启用优选IP</label>
                <div class="switch active" id="switchIP" onclick="toggleSwitch('switchIP')"></div>
            </div>
            
            <div class="switch-group">
                <label>启用GitHub优选</label>
                <div class="switch active" id="switchGitHub" onclick="toggleSwitch('switchGitHub')"></div>
            </div>
            
            <div class="form-group" id="githubUrlGroup" style="margin-top: 12px;">
                <label>GitHub优选URL（可选）</label>
                <input type="text" id="githubUrl" placeholder="留空则使用默认地址" style="font-size: 15px;">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">自定义GitHub优选IP列表来源URL，留空则使用默认地址</small>
            </div>
            
            <div class="form-group" id="preferredIPsUrlGroup" style="margin-top: 12px;">
                <label>优选IP来源URL (yxURL)（可选）</label>
                <input type="text" id="preferredIPsUrl" placeholder="留空则使用默认wetest地址" style="font-size: 15px;">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">自定义优选IP来源URL，支持HTML页面或文本格式，留空则使用默认wetest地址</small>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>协议选择</label>
                <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 8px;">
                    <div class="switch-group">
                        <label>VLESS (vl)</label>
                        <div class="switch active" id="switchVL" onclick="toggleSwitch('switchVL')"></div>
                    </div>
                    <div class="switch-group">
                        <label>Trojan (tj)</label>
                        <div class="switch" id="switchTJ" onclick="toggleSwitch('switchTJ')"></div>
                    </div>
                    <div class="switch-group">
                        <label>VMess (vm)</label>
                        <div class="switch" id="switchVM" onclick="toggleSwitch('switchVM')"></div>
                    </div>
                </div>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>客户端选择</label>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-top: 8px;">
                    <button type="button" class="client-btn" onclick="generateClientLink('clash', 'CLASH')">CLASH</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('clash', 'STASH')">STASH</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('surge', 'SURGE')">SURGE</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('sing-box', 'SING-BOX')">SING-BOX</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('loon', 'LOON')">LOON</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('quanx', 'QUANTUMULT X')" style="font-size: 13px;">QUANTUMULT X</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAY')">V2RAY</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAYNG')">V2RAYNG</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'NEKORAY')">NEKORAY</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'Shadowrocket')" style="font-size: 13px;">Shadowrocket</button>
                </div>
                <div class="result-url" id="clientSubscriptionUrl" style="display: none; margin-top: 12px; padding: 12px; background: rgba(0, 122, 255, 0.1); border-radius: 8px; font-size: 13px; color: #007aff; word-break: break-all;"></div>
            </div>
            
            <div class="form-group">
                <label>IP版本选择</label>
                <div style="display: flex; gap: 16px; margin-top: 8px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="ipv4Enabled" checked>
                        <span>IPv4</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ipv6Enabled" checked>
                        <span>IPv6</span>
                    </label>
                </div>
            </div>
            
            <div class="form-group">
                <label>运营商选择</label>
                <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispMobile" checked>
                        <span>移动</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispUnicom" checked>
                        <span>联通</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispTelecom" checked>
                        <span>电信</span>
                    </label>
                </div>
            </div>
            
            <div class="switch-group" style="margin-top: 20px;">
                <label>仅TLS节点</label>
                <div class="switch" id="switchTLS" onclick="toggleSwitch('switchTLS')"></div>
            </div>
            <small style="display: block; margin-top: -12px; margin-bottom: 12px; color: #86868b; font-size: 13px; padding-left: 0;">启用后只生成带TLS的节点，不生成非TLS节点（如80端口）</small>
        </div>
        
        <div class="footer">
            <p>简化版优选工具 • 仅用于节点生成</p>
            <div style="margin-top: 20px; display: flex; justify-content: center; gap: 24px; flex-wrap: wrap;">
                <a href="https://github.com/byJoey/cfnew" target="_blank" style="color: #007aff; text-decoration: none; font-size: 15px; font-weight: 500;">GitHub 项目</a>
                <a href="https://www.youtube.com/@joeyblog" target="_blank" style="color: #007aff; text-decoration: none; font-size: 15px; font-weight: 500;">YouTube @joeyblog</a>
            </div>
        </div>
    </div>
    
    <script>
        // 订阅token（永久有效）
        const SUBSCRIPTION_TOKEN = "${subscriptionToken}";
        
        let switches = {
            switchDomain: true,
            switchIP: true,
            switchGitHub: true,
            switchVL: true,
            switchTJ: false,
            switchVM: false,
            switchTLS: false
        };
        
        function toggleSwitch(id) {
            const switchEl = document.getElementById(id);
            switches[id] = !switches[id];
            switchEl.classList.toggle('active');
        }
        
        
        // 订阅转换地址（从服务器注入）
        const SUB_CONVERTER_URL = "${ scu }";
        
        function tryOpenApp(schemeUrl, fallbackCallback, timeout) {
            timeout = timeout || 2500;
            let appOpened = false;
            let callbackExecuted = false;
            const startTime = Date.now();
            
            const blurHandler = () => {
                const elapsed = Date.now() - startTime;
                if (elapsed < 3000 && !callbackExecuted) {
                    appOpened = true;
                }
            };
            
            window.addEventListener('blur', blurHandler);
            
            const hiddenHandler = () => {
                const elapsed = Date.now() - startTime;
                if (elapsed < 3000 && !callbackExecuted) {
                    appOpened = true;
                }
            };
            
            document.addEventListener('visibilitychange', hiddenHandler);
            
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.style.width = '1px';
            iframe.style.height = '1px';
            iframe.src = schemeUrl;
            document.body.appendChild(iframe);
            
            setTimeout(() => {
                if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
                window.removeEventListener('blur', blurHandler);
                document.removeEventListener('visibilitychange', hiddenHandler);
                
                if (!callbackExecuted) {
                    callbackExecuted = true;
                    if (!appOpened && fallbackCallback) {
                        fallbackCallback();
                    }
                }
            }, timeout);
        }
        
        function generateClientLink(clientType, clientName) {
            const domain = document.getElementById('domain').value.trim();
            const uuid = document.getElementById('uuid').value.trim();
            const customPath = document.getElementById('customPath').value.trim() || '/';
            
            if (!domain || !uuid) {
                alert('请先填写域名和UUID');
                return;
            }
            
            if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) {
                alert('UUID格式不正确');
                return;
            }
            
            // 检查至少选择一个协议
            if (!switches.switchVL && !switches.switchTJ && !switches.switchVM) {
                alert('请至少选择一个协议（VLESS、Trojan或VMess）');
                return;
            }
            
            const ipv4Enabled = document.getElementById('ipv4Enabled').checked;
            const ipv6Enabled = document.getElementById('ipv6Enabled').checked;
            const ispMobile = document.getElementById('ispMobile').checked;
            const ispUnicom = document.getElementById('ispUnicom').checked;
            const ispTelecom = document.getElementById('ispTelecom').checked;
            
            const githubUrl = document.getElementById('githubUrl').value.trim();
            const preferredIPsUrl = document.getElementById('preferredIPsUrl').value.trim();
            
            const currentUrl = new URL(window.location.href);
            const baseUrl = currentUrl.origin;
            let subscriptionUrl = \`\${baseUrl}/\${uuid}/sub?domain=\${encodeURIComponent(domain)}&epd=\${switches.switchDomain ? 'yes' : 'no'}&epi=\${switches.switchIP ? 'yes' : 'no'}&egi=\${switches.switchGitHub ? 'yes' : 'no'}\`;
            
            // 添加GitHub优选URL
            if (githubUrl) {
                subscriptionUrl += \`&piu=\${encodeURIComponent(githubUrl)}\`;
            }
            
            // 添加优选IP来源URL (yxURL)
            if (preferredIPsUrl) {
                subscriptionUrl += \`&yxURL=\${encodeURIComponent(preferredIPsUrl)}\`;
            }
            
            // 添加协议选择
            if (switches.switchVL) subscriptionUrl += '&ev=yes';
            if (switches.switchTJ) subscriptionUrl += '&et=yes';
            if (switches.switchVM) subscriptionUrl += '&vm=yes';
            
            if (!ipv4Enabled) subscriptionUrl += '&ipv4=no';
            if (!ipv6Enabled) subscriptionUrl += '&ipv6=no';
            if (!ispMobile) subscriptionUrl += '&ispMobile=no';
            if (!ispUnicom) subscriptionUrl += '&ispUnicom=no';
            if (!ispTelecom) subscriptionUrl += '&ispTelecom=no';
            
            // 添加TLS控制
            if (switches.switchTLS) subscriptionUrl += '&dkby=yes';
            
            // 添加自定义路径
            if (customPath && customPath !== '/') {
                subscriptionUrl += \`&path=\${encodeURIComponent(customPath)}\`;
            }
            
            // 添加订阅token（永久有效）
            if (SUBSCRIPTION_TOKEN) {
                subscriptionUrl += \`&token=\${encodeURIComponent(SUBSCRIPTION_TOKEN)}\`;
            }
            
            let finalUrl = subscriptionUrl;
            let schemeUrl = '';
            let displayName = clientName || '';
            
            if (clientType === 'v2ray') {
                finalUrl = subscriptionUrl;
                const urlElement = document.getElementById('clientSubscriptionUrl');
                urlElement.textContent = finalUrl;
                urlElement.style.display = 'block';
                
                if (clientName === 'V2RAY') {
                    navigator.clipboard.writeText(finalUrl).then(() => {
                        alert(displayName + ' 订阅链接已复制');
                    });
                } else if (clientName === 'Shadowrocket') {
                    schemeUrl = 'shadowrocket://add/' + encodeURIComponent(finalUrl);
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' 订阅链接已复制');
                        });
                    });
                } else if (clientName === 'V2RAYNG') {
                    schemeUrl = 'v2rayng://install?url=' + encodeURIComponent(finalUrl);
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' 订阅链接已复制');
                        });
                    });
                } else if (clientName === 'NEKORAY') {
                    schemeUrl = 'nekoray://install-config?url=' + encodeURIComponent(finalUrl);
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' 订阅链接已复制');
                        });
                    });
                }
            } else {
                const encodedUrl = encodeURIComponent(subscriptionUrl);
                finalUrl = SUB_CONVERTER_URL + '?target=' + clientType + '&url=' + encodedUrl + '&insert=false&emoji=true&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=false&fdn=false&new_name=true';
                
                const urlElement = document.getElementById('clientSubscriptionUrl');
                urlElement.textContent = finalUrl;
                urlElement.style.display = 'block';
                
                if (clientType === 'clash') {
                    if (clientName === 'STASH') {
                        schemeUrl = 'stash://install?url=' + encodeURIComponent(finalUrl);
                        displayName = 'STASH';
                    } else {
                        schemeUrl = 'clash://install-config?url=' + encodeURIComponent(finalUrl);
                        displayName = 'CLASH';
                    }
                } else if (clientType === 'surge') {
                    schemeUrl = 'surge:///install-config?url=' + encodeURIComponent(finalUrl);
                    displayName = 'SURGE';
                } else if (clientType === 'sing-box') {
                    schemeUrl = 'sing-box://install-config?url=' + encodeURIComponent(finalUrl);
                    displayName = 'SING-BOX';
                } else if (clientType === 'loon') {
                    schemeUrl = 'loon://install?url=' + encodeURIComponent(finalUrl);
                    displayName = 'LOON';
                } else if (clientType === 'quanx') {
                    schemeUrl = 'quantumult-x://install-config?url=' + encodeURIComponent(finalUrl);
                    displayName = 'QUANTUMULT X';
                }
                
                if (schemeUrl) {
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' 订阅链接已复制');
                        });
                    });
                } else {
                    navigator.clipboard.writeText(finalUrl).then(() => {
                        alert(displayName + ' 订阅链接已复制');
                    });
                }
            }
        }
        
        // 加载订阅统计
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                if (!response.ok) {
                    throw new Error('获取统计失败');
                }
                const stats = await response.json();
                
                // 更新统计数据
                document.getElementById('statActive').textContent = stats.activeCount || 0;
                document.getElementById('statGenerated').textContent = stats.generatedCount || 0;
                document.getElementById('statTotal').textContent = stats.totalAccess || 0;
                document.getElementById('ipCount').textContent = stats.allIPs || 0;
                
                // 更新IP列表下拉框
                const ipListElement = document.getElementById('ipList');
                if (stats.ipList && stats.ipList.length > 0) {
                    // 清空现有选项
                    ipListElement.innerHTML = '<option value="">请选择IP地址</option>';
                    // 添加所有IP选项
                    stats.ipList.forEach(ip => {
                        const option = document.createElement('option');
                        option.value = ip;
                        option.textContent = ip;
                        ipListElement.appendChild(option);
                    });
                    ipListElement.disabled = false;
                } else {
                    ipListElement.innerHTML = '<option value="">暂无IP记录</option>';
                    ipListElement.disabled = true;
                }
                
                // 显示内容，隐藏加载
                document.getElementById('statsLoading').style.display = 'none';
                document.getElementById('statsContent').style.display = 'block';
            } catch (e) {
                console.error('加载统计失败:', e);
                document.getElementById('statsLoading').textContent = '加载失败';
            }
        }
        
        // 页面加载时获取统计
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', loadStats);
        } else {
            loadStats();
        }
        
        // 每30秒自动刷新统计
        setInterval(loadStats, 30000);
    </script>
</body>
</html>`;
}

// 检查密码验证
async function checkPassword(request, env) {
    const password = getPassword(env);
    
    // 如果没有设置密码，则允许访问
    if (!password) {
        return { valid: true };
    }
    
    // 获取客户端IP
    const clientIP = getClientIP(request);
    const url = new URL(request.url);
    const path = url.pathname;
    
    // 检查会话
    const cookieHeader = request.headers.get('Cookie');
    if (isValidSession(cookieHeader, env)) {
        return { valid: true };
    }
    
    // 处理登录请求
    if (request.method === 'POST' && path === '/login') {
        try {
            // 检查防暴力破解保护
            const bruteForceCheck = await checkBruteForceProtection(clientIP, env);
            if (bruteForceCheck.blocked) {
                return {
                    valid: false,
                    response: new Response(generateLoginPage(bruteForceCheck.message), {
                        status: 429,
                        headers: { 
                            'Content-Type': 'text/html; charset=utf-8',
                            'Retry-After': '900'
                        }
                    })
                };
            }
            
            const formData = await request.formData();
            const inputPassword = formData.get('password');
            
            if (inputPassword === password) {
                // 密码正确，清除失败尝试记录
                try {
                    await clearFailedAttempts(clientIP, env);
                } catch (e) {
                    // 忽略清除失败的错误
                    console.error('清除失败尝试记录错误:', e);
                }
                
                // 创建会话
                const sessionToken = generateSessionToken();
                const sessionCookie = `cf_session=${btoa(Date.now().toString() + sessionToken)}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax`;
                
                // 重定向到主页
                return {
                    valid: true,
                    response: new Response(null, {
                        status: 302,
                        headers: {
                            'Location': '/',
                            'Set-Cookie': sessionCookie
                        }
                    })
                };
            } else {
                // 密码错误，记录失败尝试
                try {
                    await recordFailedAttempt(clientIP, env);
                } catch (e) {
                    // 忽略记录失败的错误
                    console.error('记录失败尝试错误:', e);
                }
                
                // 再次检查是否达到限制
                try {
                    const bruteForceCheckAfter = await checkBruteForceProtection(clientIP, env);
                    if (bruteForceCheckAfter.blocked) {
                        return {
                            valid: false,
                            response: new Response(generateLoginPage(bruteForceCheckAfter.message), {
                                status: 429,
                                headers: { 
                                    'Content-Type': 'text/html; charset=utf-8',
                                    'Retry-After': '900'
                                }
                            })
                        };
                    }
                } catch (e) {
                    // 忽略检查错误，继续返回密码错误
                    console.error('检查防暴力破解错误:', e);
                }
                
                return {
                    valid: false,
                    response: new Response(generateLoginPage('密码错误，请重试'), {
                        status: 401,
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    })
                };
            }
        } catch (e) {
            // 处理登录过程中的任何错误
            console.error('登录处理错误:', e);
            return {
                valid: false,
                response: new Response(generateLoginPage('登录处理出错，请重试'), {
                    status: 500,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                })
            };
        }
    }
    
    // 对于订阅链接，检查token而不是会话
    if (path.match(/^\/[^\/]+\/sub$/)) {
        const token = url.searchParams.get('token');
        try {
            const isValid = await isValidSubscriptionToken(token, env);
            if (isValid) {
                // token有效，允许访问订阅
                return { valid: true };
            } else {
                // token无效或不存在，需要登录
                return {
                    valid: false,
                    response: new Response('访问被拒绝：订阅链接需要有效的token。请先登录并生成新的订阅链接。', {
                        status: 401,
                        headers: { 
                            'Content-Type': 'text/plain; charset=utf-8',
                            'WWW-Authenticate': 'Basic realm="Login Required"'
                        }
                    })
                };
            }
        } catch (e) {
            console.error('验证订阅token错误:', e);
            return {
                valid: false,
                response: new Response('访问被拒绝：订阅链接验证失败。请先登录并生成新的订阅链接。', {
                    status: 401,
                    headers: { 
                        'Content-Type': 'text/plain; charset=utf-8'
                    }
                })
            };
        }
    }
    
    return {
        valid: false,
        response: new Response(generateLoginPage('请先登录以访问此页面'), {
            status: 401,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        })
    };
}

// 主处理函数
export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const path = url.pathname;
            
            // 检查密码验证（登录页面除外）
            if (path !== '/login') {
                try {
                    const passwordCheck = await checkPassword(request, env);
                    if (!passwordCheck.valid) {
                        return passwordCheck.response;
                    }
                    // 如果是登录后的重定向响应，直接返回
                    if (passwordCheck.response) {
                        return passwordCheck.response;
                    }
                } catch (e) {
                    console.error('密码验证错误:', e);
                    // 如果验证出错，返回错误页面
                    return new Response('服务器错误，请稍后重试', {
                        status: 500,
                        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
                    });
                }
            } else if (path === '/login' && request.method === 'POST') {
                // 处理登录POST请求
                try {
                    const passwordCheck = await checkPassword(request, env);
                    if (passwordCheck.response) {
                        return passwordCheck.response;
                    }
                } catch (e) {
                    console.error('登录处理错误:', e);
                    return new Response(generateLoginPage('登录处理出错，请重试'), {
                        status: 500,
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    });
                }
            }
        
        // 统计API端点
        if (path === '/api/stats' && request.method === 'GET') {
            try {
                const stats = await getSubscriptionStats(env);
                return new Response(JSON.stringify(stats), {
                    headers: { 
                        'Content-Type': 'application/json; charset=utf-8',
                        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
                    }
                });
            } catch (e) {
                console.error('获取统计信息错误:', e);
                return new Response(JSON.stringify({
                    totalAccess: 0,
                    generatedCount: 0,
                    activeCount: 0,
                    ipList: [],
                    allIPs: 0
                }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json; charset=utf-8' }
                });
            }
        }
        
        // 主页
        if (path === '/' || path === '') {
            const scuValue = env?.scu || scu;
            const homePage = await generateHomePage(scuValue, env);
            return new Response(homePage, {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
        
        // 登录页面（GET请求）
        if (path === '/login' && request.method === 'GET') {
            return new Response(generateLoginPage(), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
        
        // 订阅请求格式: /{UUID}/sub?domain=xxx&epd=yes&epi=yes&egi=yes
        const pathMatch = path.match(/^\/([^\/]+)\/sub$/);
        if (pathMatch) {
            const uuid = pathMatch[1];
            
            if (!isValidUUID(uuid)) {
                return new Response('无效的UUID格式', { status: 400 });
            }
            
            const domain = url.searchParams.get('domain');
            if (!domain) {
                return new Response('缺少域名参数', { status: 400 });
            }
            
            // 从URL参数获取配置
            epd = url.searchParams.get('epd') !== 'no';
            epi = url.searchParams.get('epi') !== 'no';
            egi = url.searchParams.get('egi') !== 'no';
            const piu = url.searchParams.get('piu') || defaultIPURL;
            // 获取优选IP来源URL (yxURL)，支持环境变量或URL参数
            const yxURL = url.searchParams.get('yxURL') || env?.yxURL || env?.YXURL || '';
            
            // 协议选择
            const evEnabled = url.searchParams.get('ev') === 'yes' || (url.searchParams.get('ev') === null && ev);
            const etEnabled = url.searchParams.get('et') === 'yes';
            const vmEnabled = url.searchParams.get('vm') === 'yes';
            
            // IPv4/IPv6选择
            const ipv4Enabled = url.searchParams.get('ipv4') !== 'no';
            const ipv6Enabled = url.searchParams.get('ipv6') !== 'no';
            
            // 运营商选择
            const ispMobile = url.searchParams.get('ispMobile') !== 'no';
            const ispUnicom = url.searchParams.get('ispUnicom') !== 'no';
            const ispTelecom = url.searchParams.get('ispTelecom') !== 'no';
            
            // TLS控制
            const disableNonTLS = url.searchParams.get('dkby') === 'yes';
            
            // 自定义路径
            const customPath = url.searchParams.get('path') || '/';
            
            return await handleSubscriptionRequest(request, uuid, domain, piu, yxURL, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, env);
        }
        
        return new Response('Not Found', { status: 404 });
        } catch (e) {
            // 捕获所有未处理的错误
            console.error('Worker 错误:', e);
            return new Response('服务器内部错误，请稍后重试', {
                status: 500,
                headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
        }
    }
};

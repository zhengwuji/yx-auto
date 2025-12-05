设置密码：
在 Cloudflare Workers 后台，进入你的 Worker
在 Settings → Variables 中添加环境变量：
- **登录验证**：使用 `ADMIN_PASSWORD` 进行身份验证 登陆密码设置
- **会话管理**：使用 `SESSION_SECRET` 签名 Cookie
- **订阅Token**：每次获取订阅链接需要有效 Token
访问网站：
首次访问会显示登录页面
输入正确的密码后即可访问主页和生成订阅
重置密码：
在 Cloudflare Workers 后台修改 LOGIN_PASSWORD 环境变量
删除该环境变量即可取消密码保护
代码已更新，可直接部署到 Cloudflare Workers。

为了获得完整的防暴力破解保护，建议：
在 Cloudflare Workers 后台创建 KV Namespace
在 Worker 设置中绑定 KV Namespace 为 AUTH_KV
这样可以在多个 Worker 实例间共享防暴力破解数据

如果修改了 LOGIN_PASSWORD 环境变量，旧的订阅链接会失效
需要重新登录并生成新的订阅链接
如果没有设置密码，订阅链接不需要 token 即可访问
# 服务器优选工具 - 简化版

## 功能特性

-  **优选域名**：自动使用内置的优选域名列表
-  **优选IP**：15分钟优选一次
-  **GitHub优选**：从 GitHub 仓库获取优选IP列表
-  **节点生成**：支持生成 Clash、Surge、Quantumult 等格式的订阅
-  **客户端选择**：支持 Clash、Surge、Quantumult X 等多种客户端格式
-  **IPv4/IPv6 选择**：可选择使用 IPv4 或 IPv6 优选IP
-  **运营商筛选**：支持按移动、联通、电信筛选优选IP

## 使用方法

### 1. 部署到 Cloudflare Workers

1. 登录 Cloudflare Dashboard
2. 进入 Workers & Pages
3. 创建新的 Worker
4. 将 `worker.js` 的内容复制到编辑器
5. 保存并部署

### 2. 使用界面


1. **输入域名**：输入您的 Cloudflare Workers 域名
2. **输入UUID**：输入您的 UUID（格式：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx）
3. **配置选项**：
   - 启用优选域名：使用内置的优选域名列表
   - 启用优选IP：从 wetest.vip 获取动态IP
   - 启用GitHub优选：从 GitHub 获取优选IP
   - 客户端选择：选择订阅格式（Base64/Clash/Surge/Quantumult X）
   - IP版本选择：选择使用 IPv4 或 IPv6
   - 运营商选择：选择移动、联通、电信运营商
4. **生成订阅**：点击"生成订阅链接"按钮

### 3. 订阅链接格式

生成的订阅链接格式为：
```
https://your-worker.workers.dev/{UUID}/sub?domain=your-domain.com&epd=yes&epi=yes&egi=yes
```

### 4. 支持的订阅格式

在订阅链接后添加 `&target=` 参数可以指定格式：

- `&target=base64` - Base64 编码（默认）
- `&target=clash` - Clash 配置
- `&target=surge` - Surge 配置
- `&target=quantumult` - Quantumult 配置

## 配置说明

### 环境变量（可选）

无需配置环境变量，所有功能通过URL参数控制。

### URL 参数

- `domain`: 您的域名（必需）
- `epd`: 启用优选域名（yes/no，默认：yes）
- `epi`: 启用优选IP（yes/no，默认：yes）
- `egi`: 启用GitHub优选（yes/no，默认：yes）
- `piu`: 自定义优选IP来源URL（可选）
- `target`: 订阅格式（base64/clash/surge/quantumult）
- `ipv4`: 启用IPv4（yes/no，默认：yes）
- `ipv6`: 启用IPv6（yes/no，默认：yes）
- `ispMobile`: 启用移动运营商（yes/no，默认：yes）
- `ispUnicom`: 启用联通运营商（yes/no，默认：yes）
- `ispTelecom`: 启用电信运营商（yes/no，默认：yes）

## 注意事项

1. **这不是代理工具**：此工具仅用于生成订阅链接，不提供代理功能
2. **需要配合其他服务**：生成的节点需要配合其他代理服务使用
3. **域名要求**：输入的域名应该是您实际使用的 服务器 域名
4. **UUID格式**：UUID 必须是标准的 UUID v4 格式

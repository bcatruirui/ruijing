# 部署和回滚

前端使用独立仓库 `bcatruirui/ruijing` 的 GitHub Pages，正式地址为 `https://ip.ruirui.uk`。检测 API 与离线情报使用 Cloudflare Workers Free。现有同源 Worker 入口用于本地验证。把缓存、临时文件和构建产物放在项目目录，参见 [README](README.md)。

## Worker 优先

1. 核实 Cloudflare 账户和 Worker 都使用 Free，且不存在计费绑定。正式 API 使用 `https://api-ip.ruirui.uk`，由 `wrangler.jsonc` 绑定至 `ruijing-ip`。保持 Pseudo IPv4 的覆盖模式关闭，以保留实际地址族。
2. 执行 `node scripts/refresh-data.mjs --force`、`npm test`、`npm run build` 和 `npm run worker:check`。核验 `reports/budget.json` 和新鲜度。正常报告必须读取有效 IPv4/IPv6 ASN、城市和网络分类来源。
3. 首次可由已登录的 Wrangler 执行 Worker 部署，并设置 `ALLOWED_APP_ORIGINS` 为 `["https://ip.ruirui.uk","https://bcatruirui.github.io"]`。发布时保持 `DNS_PUBLIC_VERIFIED=false`。启用持续更新时，在 GitHub Actions 变量设置 `INTEL_REFRESH_ENABLED=true`、`INTEL_RELEASE_ENABLED=true`、`WORKER_API_BASE`、`PAGES_ORIGIN=https://ip.ruirui.uk` 和 `CLOUDFLARE_ACCOUNT_ID`，并在 `ruijing-worker` 环境设置限定账号及所需 Worker 发布权限的 `CLOUDFLARE_API_TOKEN`。工作流 **Refresh and verify public IP intelligence** 首次部署可勾选 `bootstrap`。需要更新同一数据版本的 Worker 代码时勾选 `publish_code`。
4. 验证预览请求的 CORS、错误码、真实访客公网 IP、两种地址族、冷/热 CPU 和并发内存。跨域调用会消耗预检额度。记录最近两个成功版本 ID。故障时用 Cloudflare 控制台回滚到上一成功版本，同一 Worker 版本提供匹配的数据分片与索引。

定时任务使用标准 Linux runner，每两小时检查短效源，慢源按日检查。工作流验证后仅发布已变化的快照。可选的 `INTEL_FREE_CACHE_ENABLED=true` 复用公共快照和原始下载。保持 GitHub 默认免费缓存上限或更低，并核实账单硬停止设置后再开。独立上游任务会检查线上数据是否过期。

## GitHub Pages

1. 在仓库 **Settings → Pages** 选择 **GitHub Actions**。确认 Worker 已接受目标前端 Origin，在 **Settings → Secrets and variables → Actions → Variables** 将 `WORKER_API_BASE` 设置为 `https://api-ip.ruirui.uk`。之后推送 `main` 自动部署，也可从 Actions 手动运行 **Publish Ruijing frontend to GitHub Pages**。
2. 在 GitHub 账号 **Settings → Pages** 验证 `ip.ruirui.uk`。将 GitHub 提供的验证 TXT 记录加到 Cloudflare 并保留。在 `bcatruirui/ruijing` 仓库的 **Settings → Pages → Custom domain** 保存 `ip.ruirui.uk`，将 Cloudflare 的 `ip` CNAME 指向 `bcatruirui.github.io`，设置为 **仅 DNS**。父域 DNS 和个人网站配置保持原样。证书签发后勾选 **Enforce HTTPS**。
3. Pages 工作流读取实际域名和资源根路径。切换域名后手动再运行一次 Pages 工作流，让资源从 `/ruijing/assets/` 切换到 `/assets/`。GitHub Actions 发布通过仓库设置管理域名。本地分别以 `PAGES_BASE=/ruijing/` 和 `PAGES_BASE=/` 设置 `VITE_API_BASE`，运行 `npm run build:pages` 与 `node scripts/check-pages.mjs`。

正式站防嵌入由 HTTP 响应头提供。保留 `ip` 的 GitHub Pages CNAME 目标，在 Cloudflare 创建仅匹配 `http.host eq "ip.ruirui.uk"` 的响应头转换规则，设置 `Content-Security-Policy: frame-ancestors 'none'` 和 `X-Frame-Options: DENY`。确认边缘证书有效、代理回源使用 HTTPS 且校验源站证书后，再将该 CNAME 改为代理模式。发布验收应检查正式域名首页与说明页的响应头、HTTPS 和检测 API。若代理切换导致访问异常，将该记录恢复为仅 DNS。HTML 中的 CSP 仍负责限制前端资源加载。
4. 确认 Actions 部署成功，再验证正式 HTTPS 首页、隐私、评分说明和来源入口、IP 自查与 IPv4/IPv6 查询。检查 DNS 能力显示暂不可用。Pages 产物仅含静态页面和公共资源，使用 HTML CSP 和 Referrer Policy。

自定义域名切换时先更新 Worker 的 `ALLOWED_APP_ORIGINS`，再切换 Pages 域名。DNS 探测使用独立子域，可按 [公网 DNS 上线清单](docs/DNS_LAUNCH.md) 单独启用。WebRTC 公网 STUN、真正单地址族端点与受控分流节点分别通过 [架构配置](docs/ARCHITECTURE.md) 启用。

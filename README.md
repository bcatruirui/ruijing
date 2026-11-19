# 瑞镜 IP 检测 · Ruijing IP

瑞镜提供公网 IP 归属、纯净值、自然语言检测报告和网络隐私检查。GitHub Pages 托管前端，Cloudflare Workers Free 使用本地公开数据分片处理检测。访客查询不发送到第三方 IP 查询 API。

纯净值仅在网络分类和地址级威胁覆盖达到门槛时显示。资料不足或存在关键冲突时暂不评分。检测报告会解释可观察到的出口位置、网络类型、时区与 DNS 状态。查看 [评分规则](RISK_SCORING.md)。

## 本地运行

需要 Node.js 24 或更新版本。所有命令在本项目目录运行，缓存与下载存放项目内；Windows 请先配置本项目 `.cache`，不要让安装器写入 C 盘缓存。

```powershell
$env:npm_config_cache = "$PWD\.cache\npm"
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\.cache\browsers"
$env:TEMP = "$PWD\.cache\tmp"
$env:TMP = "$PWD\.cache\tmp"
New-Item -ItemType Directory -Force $env:TEMP | Out-Null
npm ci
node scripts/build-data.mjs --profile=quick
npm run dev
```

`quick` 使用真实 ASN、网络分类、Tor 与威胁数据，不是演示数据；不包含全球城市库。完整构建：

```powershell
node scripts/build-data.mjs --profile=standard --reuse-cache
npm test
npm run build
npm run worker:check
```

`standard` 为默认 profile，会流式转换 DB-IP City Lite 全球 CSV。`--reuse-cache` 验证本地原始文件 SHA-256 后复用，保留原始下载/发布时间；去掉该参数才重新下载。构建下载失败时相关来源独立标记不可用。正式构建若城市库失败退出非零；禁止忽略失败后宣称完整数据已部署。

本地真实快照、地址族、记录数和到期时间见 [快照记录](docs/DATA_SNAPSHOT.md) 和 `data/generated/BUILD_SUMMARY.json`。日常刷新可运行 `node scripts/refresh-data.mjs`，首次或强制全量更新加 `--force`。刷新先验证暂存文件，失败的来源可保留原快照及到期时间。

## 能力与诚实边界

- 当前 HTTP 出口从 Cloudflare 可信边缘元数据读取；手动 IPv4/IPv6 查询使用本地情报。IP 地理位置是近似网络位置，ASN 组织不是必然的零售 ISP。
- 可解释参考分数、来源命中、证据、更新时间、网络属性、中英文界面和浏览器本地报告导出。
- WebRTC 由用户启动；未配置自建 STUN 时只报告本地 ICE 能力，不能判定公网地址无泄漏。
- 真正 DNS 泄漏测试需要独立权威 DNS 与 HTTPS 资源；协议源码和配置位于 `services/`。未部署时显示未部署。
- IPv4-only、IPv6-only 与分流比较需要自己的真实测试端点；workers.dev 本身不足以提供所有端点。
- 本地请求没有真实 Cloudflare 来访元数据时，不得把回环地址或固定样例冒充用户公网 IP。

## 文档与验证

见 [部署](DEPLOYMENT.md)、[隐私](PRIVACY.md)、[安全](SECURITY.md)、[数据来源](DATA_SOURCES.md)、[评分规则](RISK_SCORING.md)、[成本与免费额度](COSTS.md)、[架构接口](docs/ARCHITECTURE.md)和[数据管道](docs/DATA_PIPELINE.md)。[实测报告](TEST_REPORT.md)和[七维审查](REVIEW.md)列出已验证项目和未达标边界；源码存在不代表功能已通过生产在线验证。

站点没有账号、访客查询历史、广告和收费 API。发布工作流须由所有者启用。GitHub Pages、Worker 部署和公网 DNS 验收分别见 [部署](DEPLOYMENT.md) 与 [DNS 上线清单](docs/DNS_LAUNCH.md)。

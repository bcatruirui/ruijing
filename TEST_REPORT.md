# 实测与验收报告

## 2026-11-19 纯净值呈现更新

`ruijing-purity-2` 为纯净值提供独立的覆盖状态。真实托管样本得到 80 分，扣分来自机房托管，两个窄覆盖来源将结果限定为参考分。451 项单元、API 和协议测试以及 8 项对应的桌面和手机浏览器测试通过。Worker dry-run 和 Pages 构建通过。

## 2026-11-19 重构验收

使用真实离线快照 `rj-001627aa0c416c30`，风险模式 `ruijing-evidence-2.0.0`，首屏纯净值规则 `ruijing-purity-1`。

| 检查 | 结果 |
| --- | --- |
| 单元、API 和网络协议测试 | 450 项通过，含真回环 UDP/TCP DNS 和会话清除 |
| Chromium 桌面和手机 | 18 项通过，2 项外网资源测试按配置跳过 |
| WCAG 2.2 AA 自动扫描 | 桌面和手机的深浅色、报告与对话框状态通过 |
| Pages 生产构建 | 独立产物，验证子路径、政策入口、无原始情报和源码映射 |
| 双源浏览器联调 | 真实跨域预检和查询通过，320/390/768/1440px 无横向溢出，实查托管样例显示纯净值 80 |
| Wrangler 与本地 workerd | dry-run 通过，公用情报访问隔离、IPv4/IPv6、no-store 和错误状态共 13 项通过 |

浏览器 DNS 报告交互使用独立 Mock 测试。公网权威 DNS、正式 Cloudflare 实例的真实访客数据、Free CPU 配额、线上 Core Web Vitals 和人工屏幕阅读器仍待部署验收。当前新鲜地址级威胁来源仅支持 IPv4，IPv6 纯净值按覆盖门槛留空。现时数据明细见 [快照](docs/DATA_SNAPSHOT.md)，公网资源见 [DNS 验收清单](docs/DNS_LAUNCH.md)。

## 2026-10-29 历史记录

日期：2026-10-29（Asia/Shanghai）。平台：Windows、Node 24、Chromium 156、TypeScript 严格模式。数据版本：`rj-5ccce22ffa287ca8`；模型：`ruijing-evidence-1.0.0`。

本报告区分规则/Mock 测试、真实本地运行和真实外网观察。没有正式部署，不把源码、dry-run 或本机成功描述成生产验证。

## 自动化结果

| 检查                     | 结果                                                                         | 证据                                                        |
| ------------------------ | ---------------------------------------------------------------------------- | ----------------------------------------------------------- |
| 单元、API 集成、网络协议 | **368/368 通过，9 个文件**                                                   | `reports/unit-integration-results.json`                     |
| 桌面与手机浏览器         | **12 通过，2 个外网用例默认跳过**                                            | `reports/e2e-results.json`、`reports/playwright/index.html` |
| 自动无障碍               | 桌面/手机、空状态/真实报告、深浅色/对话框，5 种状态各自无 WCAG A/AA 检查违规 | `reports/accessibility/`                                    |
| 依赖审计                 | npm 数据库报告 **0 个已知漏洞**，不等于不存在未知漏洞                        | `reports/dependency-audit.json`                             |
| 严格类型与生产构建       | 通过                                                                         | `reports/build-output.txt`                                  |
| Worker 打包 dry-run      | 通过，未上传                                                                 | `reports/worker-dry-run.txt`                                |
| 数据与免费静态预算       | 哈希、格式、大小、版本和文件数检查通过                                       | `reports/budget.json`                                       |

368 项由 IP 校验/匹配 120、二进制数据 62、评分 78、CSV schema 3、API 68、网络模块 37 组成。覆盖 IPv4/IPv6、最长前缀、恶意命中、仅机房/仅 VPN、住宅与住宅代理区分、缺失信息、中性基准、过期/冲突/同源去重、确定性、源不可用、私有资源隔离、请求大小/并发/限流/跨域和令牌/协议边界。评分样例多为标明的合成 fixture，不能据此报告现实欺诈识别率或误报率。

12 个浏览器用例包含 6 个真实浏览器本地检查和 6 个明确标记的 Mock 检查。真实检查包括离线数据库查询、PNG/JSON 下载、浏览器 PDF、真实本地 ICE、语言/主题/焦点/布局/无默认第三方请求；Mock 检查包括远端资源加载、受控出口和能力接口失败。390×844 和 1440×1000 CSS px 无横向页面溢出。尚未运行 Safari、Firefox、真实 iOS 或人工屏幕阅读器测试。

截图位于 `reports/screenshots/`；本地生成的示例 PNG/PDF 位于 `reports/exports/`，仅包含刻意选取的公开测试 IP。PNG 已视觉检查，PDF 首页面已渲染检查；不能据此保证所有浏览器打印设置下的所有分页。

## 真实本地数据和 Worker

实际转换 10,475,499 条公开记录；这包括大量归属和地理记录，**不是一千多万条恶意 IP**。格式 2 分片 7,277 个，537,363,503 bytes，最大 131,053 bytes；静态资产 7,293 个。来源的日期、原始 SHA-256 和许可收据保留，Feodo 旧记录明确过期且不加分。[数据记录](docs/DATA_SNAPSHOT.md)

`reports/runtime/worker-final.json` 保存本机真实 workerd 的 13 项检查：7 种情报私有路径/编码别名均 404；4 个真实离线 IPv4/IPv6 查询均 200、no-store 且数据版本一致；私有 IP 和跨域请求分别 400/403。

| 刻意选取的测试地址     | 实际快照结果                                                 |
| ---------------------- | ------------------------------------------------------------ |
| `8.8.8.8`              | ASN 15169，US/California/Mountain View；参考 50，资料不足    |
| `2001:4860:4860::8888` | 参考 51，低可信度；仅网络属性不形成严重恶意结论              |
| `2607:ff10:c8:594::a`  | FFraud 实际 C2 记录命中；参考 65、低可信度，来源没有活动日期 |
| `171.25.193.25`        | Tor 官方观察和 FFraud 记录分别可追溯；参考 61、低可信度      |

这些是该版本库的读出结果，不证明当前使用者行为，也不证明使用者的真实地理位置。无有效威胁证据的 50 分遵循后续确认的中性产品基准，不能表述为中等欺诈风险。

## 单独执行的真实在线观察

已单独执行一次桌面 Chromium 外网用例，**1 项通过**，不是默认 Mock 测试的一部分。2026-10-29 当前环境中：百度 47 ms、淘宝 111 ms、Google 523 ms、GitHub 732 ms、Cloudflare 535 ms、YouTube 520 ms、TikTok 731 ms 的所选 HTTPS 图像资源加载成功；微信资源结果不确定。证据：`reports/online/connectivity.json` 与 `reports/screenshots/online-connectivity.png`。

这些是单次资源请求耗时，不是 ICMP ping、全站可用性、账号解锁、证书链检查、SSL 劫持检测或任意站点出口 IP。请求只在主动启动后发生，可能受浏览器 Cookie/缓存/跟踪保护和中间网络影响。

复验命令：PowerShell 设置 `$env:RUN_ONLINE_PROBES='1'` 后执行 `npm run test:e2e -- tests/e2e/online.spec.ts --project=chromium-desktop`。它会按用户所选测试主动连接上述公开站点，不发送本网站查询的 IP 字段或报告；默认不运行。

## 免费运行与性能边界

Wrangler dry-run：Worker 未压缩约 1,007.23 KiB，gzip 413.26 KiB；主界面 JS gzip 约 91 KiB，高级检测按需加载。没有 KV/D1/R2、收费 API、商业数据库、部署令牌或自动开通动作。

`reports/runtime/local-v8-profile.json` 是本地 V8 采样：本次热 IPv4/IPv6 观察到约 0.51/1.09 ms 活跃 JS 样本，首次查询样本约 30.05/13.89 ms。**样本包括工具开销和本机运行时行为，不是生产 CPU 计费测量，不能证明满足 Free 的每次 10 ms。** 冷查询余量仍需生产验证；不能把较低的热样本替代它。也没有生产并发内存压测或多地区可达性保证。

## 尚未验证或未部署

- 当前访客公网 IP 的真实 Cloudflare 边缘路径：本地缺少可信边缘元数据，UI 诚实显示本地能力受限；生产路径只有合成元数据测试。
- DNS：完整独立权威协议/会话/HTTPS 源码与回环测试已交付；没有公网 UDP/TCP 53、委派、证书或生产解析器观察。
- STUN：独立 Binding 服务和回环/协议测试已交付；没有部署公网自建 STUN。
- IPv4-only、IPv6-only 和多出口分流：有真实协议实现与 Mock 验证，尚无用户控制的独立节点，界面显示未配置/无法判断。
- 住宅代理、Web 代理等没有合法有效情报覆盖的项目保持未知；不以 ASN、普通住宅属性或浏览器指纹补造结果。
- 风险模型尚无真实标注欺诈样本的统计校准；不宣称商业数据库等效准确率。

## 重现

```powershell
npm test -- --reporter=default --reporter=json --outputFile=reports/unit-integration-results.json
npm run test:e2e
npm run build
npm run worker:check
```

本机 workerd 检查先运行 `node scripts/project-command.mjs worker dev --local --ip 127.0.0.1 --port 8787 --inspector-port 9231`，再运行 `node scripts/check-local-worker.mjs`；完成后停止该临时服务。`scripts/profile-local-worker.mjs` 仅用于开发采样，不用于生产认证。

# 数据来源、授权与覆盖

数据是公开情报的有限快照。新增云地址目录于 2026-11-19 核查。更新前须核实上游许可和配额。

| 来源                                                                                     | 用途与更新                                        | 本项目采用的许可                                                 | 解释边界                                                                            |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [IPtoASN](https://iptoasn.com/)                                                          | IPv4/IPv6 区间、ASN、组织描述、国家；上游小时更新 | [PDDL 1.0](https://opendatacommons.org/licenses/pddl/1-0/)       | BGP 归属不是用户身份，组织描述不必然是零售 ISP，国家信息不能定位个人                |
| [DB-IP City Lite](https://db-ip.com/db/download/ip-to-city-lite)                         | 全球近似省/市；月度                               | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)        | 结果页与导出须回链 [DB-IP](https://db-ip.com/)并说明转换；Lite 覆盖和精度低于商业库 |
| [OpenASN Tier A](https://github.com/openasn/openasn)                                     | 网络分类与公开 VPN/托管信号；滚动发布             | CC0 core，保留 RouteViews CC BY 与 X4B/Brian MIT 原始 notices    | 不混入 Tier B；ASN/ISP 分类是网络推断，不能确认住宅代理或恶意                       |
| [Tor CollecTor](https://collector.torproject.org/recent/exit-lists/)                     | Tor 出口观察；通常小时更新                        | [Tor Metrics CC0](https://metrics.torproject.org/collector.html) | Tor 是隐私属性，不是恶意活动；观察时间与列表发布时间分别保留                        |
| [FFraud confirmed-abusive](https://github.com/FFraud-com/ip-fraud-database)              | 公开滥用分类与列表命中                            | MIT，保留完整 LICENSE                                            | 不采用供应商分数；confirmations 不是独立来源数；无活动日期不假装近期观察            |
| [Feodo Tracker recommended](https://feodotracker.abuse.ch/blocklist/)                    | C2 基础设施观察                                   | [abuse.ch 条款 §3.4 CC0](https://abuse.ch/terms-of-use/)         | 保留 `last_online`，过期记录不因重新下载而恢复新鲜度                                |
| [Cloudflare Request.cf](https://developers.cloudflare.com/workers/runtime-apis/request/) | 当前 HTTP 连接的边缘 ASN、近似位置与协议          | Workers Free 提供的元数据                                        | 仅适用当前连接，不是任意 IP 的查询 API；日期不可知时明确无上游精确更新时间          |
| [AWS 地址目录](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) | EC2 公开 IPv4/IPv6 前缀 | 官方公开前缀，在服务端使用 | 命中提供云服务属性 |
| [Google Cloud 地址目录](https://cloud.google.com/compute/docs/faq#find_ip_range) | Google Cloud 公开 IPv4/IPv6 前缀 | 官方公开前缀，在服务端使用 | 命中提供云服务属性 |
| [Microsoft Azure 地址目录](https://www.microsoft.com/en-us/download/details.aspx?id=56519) | AzureCloud 公开 IPv4/IPv6 前缀，周度 | 官方公开前缀，在服务端使用 | 命中提供云服务属性 |

## 授权凭据和处理方式

- [DB-IP ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite) 为 IPv4/IPv6 ASN 的月度备份，采用 CC BY 4.0 并保留 DB-IP 署名。优先使用仍有效的 IPtoASN 分片。
- [ipverse/as-metadata](https://github.com/ipverse/as-metadata) 的 CC0 分类和 DB-IP ASN 有限关联。在细粒度分类缺失时提供托管、企业和教育背景。泛 ISP 类不能确认住宅、移动或代理，OpenASN 与 ipverse 的分类也不能视作独立情报。
- [Carpathian](https://carpathian.ai/threat-intelligence) 采用 CC BY 4.0。仅保留近期窗口内有重复 IDS 记录的原生观测，第三方标签和没有明确时区的活动时刻不计入活动时效。
- [SANS ISC DShield](https://www.dshield.org/feeds_doc.html) 要求保留署名且不允许转售数据。仅导入同时满足多目标和多报告门槛的 TCP 观测。转换结果用于低可信度扫描信号，未命中仅描述该列表。Carpathian 和 DShield 都按[评分规则](RISK_SCORING.md)计入窄覆盖检查。
- 云厂商前缀只用于判定已命中的网络用途。归属证据附上原始来源。站点仅返回当前 IP 的匹配信息，快照留在服务端。

构建时只下载固定官方或已审查仓库 URL，无访客 IP 参数。原始下载元数据在 `data/cache/*.metadata.json`，记录 URL、下载时间、Last-Modified（若有）、SHA-256 与大小。生产分片和清单位于 `data/generated/`，包含来源发布、下载、到期、状态、分片哈希和许可信息。

OpenASN 从同一 release 获取 manifest、portable core CSV 与 attribution，并验证 SHA-256、格式、分类 profile、lookup policy 与 Tier A 标识。上游 MIT 和 RouteViews 许可文本按发布声明的仓库 commit 下载并校验。完整 notices 保存在 `docs/third-party/`；FFraud MIT 也随数据构建保存。不要删除这些文件后再分发衍生数据。

全球大 CSV 使用流式解压和区间切片，不在 Worker 或浏览器全量加载。小型威胁源可以在构建进程有界内存内排序；运行时仍只在后端查询。数据更新失败只影响对应来源，不把失败当作未命中。

## 分类与证据

住宅 ISP、商业网络和住宅代理是不同概念。OpenASN `residential_isp` 是 ASN 属性推断。`x4b_dc` 线索可能覆盖 VPN 或其他非接入网络，报告保留「疑似机房」的解释。没有独立住宅代理数据源时，该指标保持未知。

FFraud 是聚合列表，其自身及同源转发不可按不同来源重复计算。Feodo 是实际 C2 观察，但一个标记 online、`last_online` 已久远的记录仍应按实际时间衰减或排除，不能当作当前攻击。

黑名单“未命中”只表示本次已成功查询的适用快照没有记录。未部署、下载失败、缺片、来源过期、未提供对应类别均不是确认安全。没有公开证据的 Web 代理、搜索爬虫、住宅代理和 ASN 恶意率不得从组织名字猜测。

## 审查后未默认接入

FireHOL/IPsum 是聚合器，各上游许可及血缘不能自动继承；IP2Proxy Lite 当前使用与再分发条款需要逐项核查；Spamhaus 对公开服务和数据再分发存在用途限制；ThreatFox/URLhaus 的当前访问/商业条件不可默认永久免费。因此这些候选不因名称出现在需求中就自动下载上线。云厂商和 Apple 公布的地址段也不自动等于授予第三方再分发许可。

不抓取 Scamalytics 商业报告，不使用或重新包装其专有分数。参考网站仅用于研究信息结构与独立 UI 设计。

## 本次实际快照与新鲜度

当前交付快照与逐源数量见 [DATA_SNAPSHOT](docs/DATA_SNAPSHOT.md)，来源状态必须以运行时到期检查为准，不能长期把该表当实时状态。

OpenASN 使用仓库指定的 **`releases/download/latest/<file>`** tag-address URL，不使用含义不同的 `releases/latest/download/<file>`。下载到的 manifest 明确声明 build_id 为 `2026-10-21T08:35:31Z`；虽然上游描述为 nightly rolling，本项目没有证据证明 10 月 21 日之后每夜都成功更新，不能将 10 月 28 日下载称为 10 月 28 日发布。该网络分类快照按项目 30 天窗口到期。

FFraud 的发布元数据、CSV 和许可固定在同一提交，按发布日计算有效期。CSV 缺少单条活动日期，命中时按缺活动日期的规则计算。重新下载不会重置有效期。Feodo 也保留 `Last-Modified` 和 `last_online`。通过校验的过期地址级风险命中按[历史权重](RISK_SCORING.md)计分。

Tor 与 Feodo 本次实际快照只有 IPv4 分片，IPv6 不视为已检测未命中。FFraud、OpenASN 和 DB-IP 本次有实际 IPv4/IPv6 数据。

## 页面底图

IP 检测总览使用 Natural Earth 公共领域的 [1:110m 陆地轮廓](https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson)，预先投影为随前端打包的画布路径。标记坐标取自当次 IP 归属数据。 [Natural Earth 使用条款](https://www.naturalearthdata.com/about/terms-of-use/)

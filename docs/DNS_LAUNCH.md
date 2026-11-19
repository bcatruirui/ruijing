# 公网 DNS 检测上线清单

首发接口已接入现有自持权威 DNS 服务。正式环境默认 `DNS_PUBLIC_VERIFIED=false`，页面显示「暂不可用」。配置真实资源并完成以下公网验收后再启用。

| 缺少的资源 | 最小要求 |
| --- | --- |
| 探测域名 | 可通过 NS 记录委派独立子域，对权威 NS 具有控制权 |
| 权威主机 | 自有常在线设备或核实为零账单的资源，可从公网访问 UDP/TCP 53，配置正确信任边界 |
| HTTPS | 探测通配域名与会话 HTTPS API 均有有效证书，通配证书使用 DNS-01 并验证续期 |
| 真实验收记录 | 从运营商 DNS、公共 DNS 和浏览器加密 DNS 实测 QNAME 对应的来源解析器，核验会话删除及隔离 |

## 部署先后

1. 优先使用已有资源。没有固定公网入口时，核实运营商、CGNAT 和 53 端口限制。有条件可评估 [Oracle Always Free](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm) 的地区容量与闲置回收。
2. 参照 [权威服务说明](../services/authoritative-dns/README.md) 部署 Node 服务。通配 TLS 建议将准确的 `_acme-challenge` 记录委派给可使用最小权限更新 TXT 的 DNS 区域，验收续期。无需向 GitHub Pages 通配指向任意探测子域。
3. 用另一网络验证委派与权威回答。在同一会话触发多个随机名称，验证实际递归解析器地址和每个解析器观测到的不同名称计数。不同 ASN 或地区只表示路径差异。用已知预期 AS 或递归出口 CIDR 验证重复偏离提示、正确路径与缺少归属时的状态。分别复验过期、取消、无观测和服务失联。
4. Worker 配置 `DNS_SERVICE_URL` 和密钥 `DNS_SERVICE_SECRET`。域名填入 Pages 的 `DNS_PROBE_ZONE`，重新发布前端以更新 CSP。仅在真实验收成功后设定 `DNS_PUBLIC_VERIFIED=true`。Worker 的鉴权健康检查确认服务可访问。上线后没有真实解析数据时保留无观测或超时状态，关闭开关可即时恢复暂不可用。

## Cloudflare Free 验证记录

文档验证显示 Workers 的 HTTP 入口无法代替公网 UDP/TCP 53。免费 DNS Analytics 有查询名和来源 IP 维度，并采用自适应采样，区域查询历史保留约 31 天。若有测试账户与隔离域名，可在 `settings.availableFields` 核对 GraphQL 字段，用随机测试查询验证实际来源字段、配对率及延迟。当前没有目标账户及测试域名，账户内实测待确认。生产会话使用受控权威服务短期内存，默认 150 秒、最长 180 秒，结束主动删除。 [Workers 协议](https://developers.cloudflare.com/workers/reference/protocols/) · [Cloudflare DNS Analytics](https://developers.cloudflare.com/dns/additional-options/analytics/) · [字段发现](https://developers.cloudflare.com/analytics/graphql-api/features/discovery/settings/)

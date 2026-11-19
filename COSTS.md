# 免费运行成本与额度

核查日期：2026-11-19。基础设计新增付费依赖为 0；免费计划存在容量上限，因此不能承诺无限流量和可用性。未授权不创建云资源或执行部署。

| 依赖                  | 零费用条件                                                                     | 达到限制后的处理                                     |
| --------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------- |
| GitHub Pages | 公共仓库与标准 runner，前端产物短期保留 | 100 GB/月为软带宽限制 |
| Workers Free          | 账户保持 Workers Free；动态请求共享 100,000/日、10 ms CPU/调用、128 MB/isolate | 免费超额失败，禁止自动升级 Paid                      |
| Workers Static Assets | 静态直出请求免费不限量、存储无额外费用；20,000 文件/版本、25 MiB/单文件        | 构建超限制失败；Worker-first 路由仍消耗动态额度      |
| workers.dev           | Cloudflare 账户自带子域名，无需新域名                                          | 不提供本项目承诺的 SLA、全地区可达性或真正双协议隔离 |
| 开放数据              | 仅使用已审查永久免费授权的快照，保留署名与通知                                 | 许可变化或来源失败即停止该源/标不可用                |
| GitHub Actions        | 公共仓库标准 Ubuntu runner；仅上传轻量 Pages 产物            | 私有仓库工作流默认不运行；不自动转付费 runner        |
| 可选 DNS/STUN         | 用户已有合格资源且确认新增费用为 0                                             | 没有资源则不部署、显示未部署                         |

官方最新 Worker 脚本上限为**未压缩 64 MiB**，没有压缩大小上限；旧的 Free 3 MB 压缩资料已不适用。项目自设 128 KiB 分片、18,000 静态文件、1 MiB 精简索引、8 MiB 公共分片 LRU 与每个 IP 查询 9 次分片读取预算；它们不是官方额度。[平台限制](https://developers.cloudflare.com/workers/platform/limits/)、[静态资产计费](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/)

当前数据、构建与资产大小见 [数据库快照](docs/DATA_SNAPSHOT.md) 和 `reports/budget.json`。GitHub Pages 产物仅含前端文件。私有情报分片由 Worker 资产绑定读取。

预检和 DNS 轮询计入 Workers 请求额度。Wrangler dry-run 与本地采样只用于验证构建和评估本机行为。真实边缘 10 ms CPU 限制、并发内存和正式域名表现仍须在目标 Free 账户中检查。

## 防止自动账单

不绑定 KV、D1、R2、Queues、Containers、AI、付费日志导出或商业查询 API。Free 本身有硬限制；如所有者账户已经是 Paid，本项目不能保证其共享账户不会计费，必须在发布前核实。不要把“预算告警”当成“硬性停止”。[Workers 定价](https://developers.cloudflare.com/workers/platform/pricing/)

GitHub Free 私有仓库通常含每月 2,000 分钟、500 MB artifact、每仓库 10 GB cache；超过额度且有支付方式可能收费，Larger runners 即使公共仓库也收费。无有效付款方式时超额阻止；如使用预算必须选择 `Stop usage when budget limit is reached`，注意新预算不覆盖创建前用量。本项目仅使用公共仓库标准 runner。产物上传仅用于 GitHub Pages。大数据缓存默认关闭，经确认免费额度和硬停止条件后可自行启用。[Actions 计费](https://docs.github.com/en/billing/concepts/product-billing/github-actions)、[硬预算](https://docs.github.com/en/billing/how-tos/set-up-budgets)

DB-IP 全球城市 CSV 约数百 MB，下载、解压、构建需本地磁盘和网络。原始缓存、构建产物和依赖会消耗现有设备资源；“新增服务账单为 0”不表示没有维护、带宽、电力或人工成本。推荐至少预留数 GB 项目磁盘空间，禁止将缓存自动移至 C 盘。

Oracle Cloud Always Free 涉及卡片验证、地区容量、实例回收和误配置收费风险，不是无条件零账单承诺，不自动开通。若没有已验证的合格资源，DNS、STUN、独立协议节点保持未部署。

截至核查日，Oracle 官方列出 A1 每月 1,500 OCPU 小时与 9,000 GB 小时，相当于总计 2 OCPU/12 GB；旧的 4 OCPU/24 GB 教程已过时。另有至多两个 E2.1.Micro 和共享 200 GB 块存储额度，受家乡区域容量约束；低利用实例可能被回收。官方表示卡用于验证，未升级账户不扣款；本项目仍不自动注册、升级或选择任何试用付费资源。[Always Free 当前规格](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)、[账户与卡片说明](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier.htm)

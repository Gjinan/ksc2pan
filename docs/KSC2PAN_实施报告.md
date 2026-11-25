# KES/KSC 到 Palo Alto 防火墙 IP 联动封禁
## 方案调研、系统实现与实施报告

| 项目 | 内容 |
|---|---|
| 文档编号 | SEC-IAC-2026-001 |
| 版本 | V1.0 |
| 日期 | 2026-11-25 |
| 适用环境 | 卡巴斯基 KES 11/12 + KSC 13.2/14.x/16.x；Palo Alto PAN-OS 10.x/11.x（含 HA 双机） |
| 交付物 | 本报告 + 可运行代码包 ksc2pan（36 个自动化测试全部通过） |
| 前置约束 | 无 SIEM；防火墙不能直接消费 KES/KSC 告警；软件可自部署；优先开源 |

---

## 0. 摘要

### 0.1 结论

1. **GitHub 上不存在"KSC/KES → Palo Alto 自动封禁"的现成项目。** 相关开源件只能覆盖其中一段：
   日志管道（Vector）、防火墙执行 SDK（pan-os-python）、EDL 输出组件（CrowdSec blocklist-mirror）。
   中间"提取哪个 IP、要不要封、封多久、怎么审计"的业务决策层必须自建，而这恰好是代码量最小、
   价值最高的部分。

2. **推荐并已实现架构**：

   KES → KSC（Syslog RFC5424）→ Vector（解析粗筛）→ KSC2PAN（白名单/分级/TTL/审计）
   → 双通道下发：DAG（秒级、带 TTL、到期自动解封）+ EDL（长期清单）→ PA Drop

3. **执行面必须双通道，不能只用 EDL。** EDL 最短刷新 5 分钟、没有 TTL、认证失败会 fail-open；
   而 PAN-OS 的 User-ID `registered-ip` 支持 1 秒到 30 天的 timeout，秒级生效、免 commit、
   到期自动解封，是"临时封禁 + 误封自愈"的最优载体。

4. **防误封靠机制而非纪律**：四层白名单 + 三处拦截 + 默认 TTL + 首次只观察 + 内网源永不自动封 +
   恶意域名不转 IP。其中"三处拦截"的第三处放在防火墙上（策略 negate 白名单地址组），
   即使应用层逻辑出错也不会真的断业务。

5. **最大工程风险不在防火墙侧，而在 KSC 事件格式的解析稳定性。** 字段位置随 KES 版本与界面语言漂移，
   因此代码里把解析做成独立模块 + 20 余条断言，升级前必须回归。

### 0.2 已交付内容

| 交付物 | 说明 |
|---|---|
| 服务代码 | Python 3.12 / FastAPI，约 2100 行（含注释）；决策/执行/编排核心约 700 行 |
| 自动化测试 | 36 个用例（解析/白名单/决策/服务/API），全部通过 |
| 冒烟自检 | 10 项检查，对真实 uvicorn 实例执行，全部通过 |
| 样本回放 | 12 条脱敏样本，覆盖观察/封禁/升级/白名单/内网/域名/脏数据 |
| 部署编排 | docker compose（服务 + Vector + Nginx EDL），离线可导入 |
| 配置模板 | config.yaml（策略阈值）+ whitelist.yaml（同事维护）+ vector.toml + nginx 配置 |
| 文档 | 本报告 + 代码仓 README（含运维命令） |

---

## 1. 需求与约束

### 1.1 现状

- 终端侧：KES 统一由 KSC 管理，能检出"网络攻击""可疑网络活动""网络连接被阻止"等事件，
  事件里带有对端（攻击源）IP。
- 边界侧：Palo Alto 承担南北向访问控制，具备 EDL、User-ID API 等可编程能力。
- 缺口：两者之间没有任何通道。没有 SIEM，PA 也不能直接读 KSC 的告警。

### 1.2 目标与非目标

| 目标 | 说明 |
|---|---|
| G1 | 终端检出攻击后，秒级在边界封禁攻击源 IP，无需人工 |
| G2 | 封禁必须可自动过期，误封能自愈，且能随时人工撤销 |
| G3 | 同事可自助维护白名单网段，变更留痕、可审计 |
| G4 | 全链路可解释：每个 IP 为什么被封、依据哪条事件、谁批的 |
| G5 | 单机可部署、离线可运行、无商业组件依赖 |

| 非目标 | 原因 |
|---|---|
| N1 | 不做全流量检测/威胁狩猎（那是 NDR/SIEM 的职责） |
| N2 | 不做终端隔离（由 KSC 任务/EDR 执行，本方案只出工单建议） |
| N3 | 不做域名/IP 情报 enrichment（可后续接威胁情报） |
| N4 | 不替代边界既有 IPS（PA 自身 Threat/Zone Protection 继续保留） |

### 1.3 为什么必须加一层中间件

| 设想 | 为什么不可行 |
|---|---|
| PA 直接订阅 KSC 告警接口 | PAN-OS 只能拉取 EDL 纯文本，或接收 User-ID XML，不认识 KSC 的 RPC/JSON |
| KSC 直接把事件推给 PA | KSC 只支持 syslog/CEF/LEEF 文本导出，PA 的 syslog 接收用于存日志，不做"提取 IP 再封禁" |
| 用 KSC 的网络隔离替代 | 那是终端侧动作（断网/限制），无法表达"只封某源 IP 的入站"，且影响终端自身业务 |

因此中间层不可避免。但它的体量很小：一台 2C4G 虚机、三个容器即可承载数千终端。

---

## 2. 技术前提

以下 8 条是方案的地基，均已在厂商文档中核实（见附录 D）。

| 编号 | 事实 | 对本方案的影响 |
|---|---|---|
| F1 | KSC 支持将事件导出为 Syslog（RFC5424），可选 TCP/UDP/TLS | 提供实时事件流，且不需要额外授权 |
| F2 | CEF/LEEF 仅支持"通用事件"，应用专有事件必须用 Syslog 格式 | 必须选 Syslog，不能图省事选 CEF |
| F3 | 导出范围由"策略 → 事件配置 → 使用 Syslog 导出到 SIEM"逐条勾选控制 | 可在源头削减 90% 噪音 |
| F4 | KSC syslog 报文形如 `[event@11111 p1="…" et="…" hip="…" hdn="…"] 正文` | 可稳定提取事件码与终端 IP；对端 IP 位置不稳定（主要风险） |
| F5 | KSC OpenAPI（13299）可按事件类型、时间窗查询 | 可作为对账/回补通道，弥补 syslog 无重传 |
| F6 | PA EDL：最多 30 个自定义列表；IP 条目 5 万（多数型号）/15 万（高端）；最短 5 分钟刷新 | 容量与实时性都不足以单独承担封禁 |
| F7 | PA EDL 在源不可达时沿用旧表，但**认证失败会停止执行该列表** | 不能给 EDL 配 Basic Auth；必须监控拉取状态 |
| F8 | PA User-ID `registered-ip` 支持 tag timeout 1 秒~30 天，免 commit，重启后非持久 | 适合临时封禁；启动必须重放 |

> 推论：**实时封禁走 DAG，长期清单走 EDL**；两者失败模式互补，正好覆盖"误封自愈"和"大批量"两个诉求。

---

## 3. 方案选型

### 3.1 调研范围与方法

检索 GitHub 全站（关键词：KSC/KES 事件解析、KSC OpenAPI 客户端、Palo Alto EDL / DAG / User-ID、
EDL server、threat feed to firewall、fail2ban + firewall、CrowdSec 防火墙集成），
并逐一核对仓库的最近提交时间、Star 数、许可证、是否归档。

### 3.2 候选对比

| 项目 | 角色 | 维护状态（2026-11-25） | 许可证 | 结论 |
|---|---|---|---|---|
| crowdsecurity/crowdsec | 决策/信誉引擎 | 活跃，1.58 万 Star | MIT | 可选增强；无 Kaspersky 解析器 |
| cs-blocklist-mirror | EDL 输出端点 | 维护中，23 Star | MIT | 可复用（选 CrowdSec 路线时） |
| fail2ban | 日志→计数→动作 | 非常活跃，1.9 万 Star | GPL-2.0 | 仅适合小规模 PoC |
| Vector | 日志管道 | 活跃 | MPL-2.0 | 采用（解析层） |
| Fluent Bit | 日志管道 | 活跃 | Apache-2.0 | 备选，资源更省 |
| pan-os-python | PA SDK | 活跃，402 Star | ISC | 采用（执行层思路） |
| KineticLull | EDL 管理器 | 2026-11 有提交，6 Star | MIT | 可选，不解决采集 |
| ejohnfel/edl | 轻量 EDL 写入 | 2026-08，0 Star | MIT | 理念可借鉴 |
| OpenEDL | EDL 管理器 | 2026-07 新建，2 Star | 无许可证 | 排除（合规风险） |
| MineMeld 系列 | 旧 TIP 流水线 | 全部已归档（EOL） | Apache-2.0 | 不用于新项目 |
| KSC→Wazuh decoders | 解析参考 | 2024-08 后停更，27 Star | 无许可证 | 仅读格式，不复制代码 |
| Wazuh | SIEM/HIDS | 活跃 | GPL-2.0 | 超出范围，作为演进路径 |

### 3.3 选型结论

- **端到端项目：不存在。** 差距在于"业务决策层"，不是缺零件。
- **最终组合**：Vector（采集解析）+ 自建 KSC2PAN（决策与审计）+ PAN-OS 原生 DAG/EDL（执行）。
- **不引入 CrowdSec/fail2ban 的理由**：本项目只需要"A 类事件 → B 类动作"的确定性映射，
  引入通用引擎会带来额外概念、YAML 与运维负担，且它们的白名单/分级/审计能力弱于自建。
  若后续要接蜜罐、WAF、扫描器等多源情报，再把 CrowdSec 挂到 KSC2PAN 前端即可（演进路线见第 12 章）。
- **许可证合规**：全部采用 MIT/MPL-2.0/ISC/Apache-2.0；对"无许可证"的两个项目只做格式参考，
  不复制其代码。

---

## 4. 总体设计

### 4.1 架构

```
┌──────────────┐  ①事件上报    ┌────────────────────┐
│ KES 终端群   │ ───────────► │ KSC 管理服务器      │
│ Win / Linux  │              │ 事件导出→Syslog     │
└──────────────┘              └─────────┬──────────┘
                                        │ ②RFC5424 / TCP-TLS（6514）
                                        ▼
                          ┌──────────────────────────────┐
                          │ Vector                       │
                          │ syslog 解析 + 事件码粗筛      │
                          │ 磁盘缓冲 + 死信分流           │
                          └───────────┬──────────────────┘
                                      │ ③NDJSON（内网 8080）
                                      ▼
        ┌──────────────────────────────────────────────────────────┐
        │ KSC2PAN（自建，FastAPI + SQLite）                          │
        │  解析 → IP 校验 → 方向/私网 → 白名单四层 → 阈值分级 → 动作 │
        │  状态：events / blocks / audit；白名单：Git 版本化 YAML    │
        └───┬───────────────────┬──────────────────┬───────────────┘
            │ ④User-ID API      │ ⑤写 EDL 文件      │ ⑥审计/告警
            ▼                   ▼                  ▼
     ┌──────────────┐   ┌────────────────┐   ┌──────────────┐
     │ PA DAG       │   │ Nginx EDL 端点 │   │ 企微/邮件(可选)│
     │ tag=KES-BLOCK│   │ ip-block.txt   │   └──────────────┘
     │ timeout=4h   │   │ domain-sink.txt│
     └──────┬───────┘   └───────┬────────┘
            │ 秒级               │ 5 分钟
            ▼                    ▼
     ┌──────────────────────────────────────────────────────────┐
     │ Palo Alto（HA 双机）                                       │
     │ Drop 策略（置于 allow 之前）+ 日志 + 源地址 negate 白名单组 │
     └──────────────────────────────────────────────────────────┘
```

### 4.2 组件职责

| 组件 | 职责 | 不负责 |
|---|---|---|
| KSC | 产生事件、按勾选规则导出 syslog | 不做任何封禁判断 |
| Vector | 协议终止、TLS、磁盘缓冲、按事件码粗筛、死信分流 | 不做白名单与阈值判断 |
| KSC2PAN | 权威解析、白名单、分级、TTL、下发、审计、对账、熔断 | 不做流量检测 |
| Nginx | 以纯文本暴露 EDL，禁止缓存、限制来源 | 不做鉴权（避免 fail-open） |
| PA | 执行 Drop、日志、白名单 negate 兜底 | 不做事件解析 |

### 4.3 代码结构

| 模块 | 行数级别 | 关键点 |
|---|---|---|
| ksc_parser.py | 260 | RFC5424 解析；三级 IP 提取（结构化字段→带标签正文→全文兜底）；事件分类 |
| normalize.py | 140 | IP 归一化（含端口/方括号）；L0 保留段；CIDR 聚合 |
| whitelist.py | 300 | 四层模型；加载期校验（过宽网段/缺字段/条目暴涨）；热加载失败保留旧配置 |
| policy.py | 160 | 纯决策函数，11 个出口分支，全部可单测 |
| store.py | 300 | SQLite；事件计数用"入库时间"而非"事件时间"（应对 KSC 补发历史事件） |
| enforcer.py | 260 | XML API 批量注册/注销；HA 逐台推送；EDL 原子写（tmp+rename） |
| service.py | 380 | 编排 + 周期任务（到期解封、白名单反查、EDL 刷新、日志裁剪） |
| main.py | 180 | HTTP 路由；NDJSON/单条/原始行三种入参；可选 token 鉴权 |

### 4.4 关键设计决策

| 决策 | 理由 | 被否方案 |
|---|---|---|
| DAG 承担实时封禁 | 有 timeout、秒级、免 commit | 只用 EDL：5 分钟延迟 + 无 TTL |
| 白名单三处拦截 | 单点拦截必然被"事后加白"绕过 | 只在入库前过滤 |
| 第三处拦截放防火墙上 | 应用层 bug 不应直接变成断网事故 | 只靠应用层 |
| 计数用入库时间 | KSC 补发积压事件时，用事件时间会导致"全部过期、永不封禁" | 用事件时间计数 |
| 内网源 IP 永不自动封 | 横向移动封 IP = 封自己人/封整栋楼 | 统一按 IP 封 |
| 域名事件不转 IP | CDN/共享主机/云 WAF 回源误封面极大 | URL→解析→封 IP |
| 首次只观察 | IDS 误报不应立刻断业务；攻击者通常重复，二次即封 | 首见即封 |
| 待审批期间保持临时封禁 | 避免"等审批"变成"不封"的窗口 | 待审批即放行 |
| EDL 不配 Basic Auth | 认证失败会 fail-open（F7） | 用认证"更安全"的直觉 |
| dry_run 默认 true | 默认安全侧，灰度后才下发 | 默认即封 |

---

## 5. 数据流

### 5.1 单条事件的旅程

| 步骤 | 动作 | 失败处理 | 时延 |
|---|---|---|---|
| 1 | KES 检出网络攻击，上报 KSC | 终端离线则延后 | 1~10 s |
| 2 | KSC 按勾选规则以 Syslog 推送 | TCP 断则 Vector 磁盘缓冲 | <1 s |
| 3 | Vector 解析并粗筛（非网络类丢弃） | 事件码为空 → deadletter | <1 s |
| 4 | KSC2PAN 权威解析，取对端 IP | 无 IP → ignore 并计数 | <1 s |
| 5 | IP 校验 + 方向/私网判定 | 内网 → 工单建议 | <1 s |
| 6 | 白名单四层比对 | 命中 → 审计 WL-HIT | <1 s |
| 7 | 阈值/严重度分级 | 未达标 → 观察名单 | <1 s |
| 8 | DAG 注册（带 timeout）或写 EDL | PA 不可达 → 指数退避重试 | 1~3 s |
| 9 | 写 blocks + audit | — | — |
| 10 | 到期由 PA 自动解封；EDL 由服务每日重算 | — | 自动 |

端到端：DAG 通道约 5~15 秒；EDL 通道 5~10 分钟。

### 5.2 失败降级

| 故障 | 期望行为 |
|---|---|
| Vector 停止 | KSC 侧 TCP 背压或丢弃；恢复后补发；可用 OpenAPI 对账补齐 |
| KSC2PAN 停止 | 已有封禁按 TTL 自然到期，不会永久残留 |
| PA API 不可达 | 本地队列重试 + 告警；不写 EDL，避免"写了但没生效"的错觉 |
| EDL 拉取失败 | 监控 `show system external-list` 与系统日志；保持无认证 + IP ACL |
| 服务重启 | 启动时按 SQLite 重放未过期封禁（F8） |
| 误封扩散 | `estop` 一键停止下发，或用 `revoke` 单条撤销 |

---

## 6. 封禁决策

### 6.1 事件分类与 IP 语义

| 事件类别 | 典型事件码 | IP 含义 | 处置 |
|---|---|---|---|
| 入侵防御/网络威胁 | GNRL_EV_ATTACK_DETECTED、000007d1、00000329、00000abe | 对端/攻击源（入站） | 进入封禁主流程 |
| Web 威胁 | GNRL_EV_WEB_URL_BLOCKED 等 | 恶意 URL/域名 | 只写 domain-sink（DNS sinkhole） |
| 病毒查杀 | GNRL_EV_VIRUS_FOUND 等 | 无外部 IP | 忽略，转端点隔离 |
| 其他/未知 | 0000xxxx | 多为无对端信息 | 忽略并计数 |

### 6.2 决策顺序（与代码一致）

1. 熔断开关 → 直接跳过
2. 类别闸门：非网络入站 → 忽略
3. 内网/保留段 → 转主机隔离工单（不封）
4. 白名单命中 → 只审计
5. 时间窗 observe_only → 只观察
6. 阈值升级判定（主机数/24h 次数）→ 待审批或长期
7. 已在封禁 → 续期并更新计数
8. 容量保护（活跃封禁超上限）→ 只观察
9. 首次出现 → 只观察
10. 严重事件 → 临时封禁（跳过次数阈值）
11. 达到基础阈值 → 临时封禁
12. 未达阈值 → 观察

### 6.3 默认阈值与 TTL

| 参数 | 默认值 | 说明 |
|---|---|---|
| dag_ttl_seconds | 14400（4 小时） | 临时封禁时长，PA 侧 timeout |
| edl_ttl_days | 30 | 长期封禁保留天数 |
| dag_min_hits | 2 | 24h 内第几次进入临时封禁 |
| critical_immediate | true | 严重事件不等次数阈值 |
| edl_min_hosts_10m | 3 | 10 分钟内命中主机数达 3 → 升级候选 |
| edl_min_hits_24h | 10 | 24h 累计次数达 10 → 升级候选 |
| require_approval_for_edl | true | 升级需人工确认 |
| max_blocks | 5000 | 活跃封禁上限 |

### 6.4 分级动作

| 级别 | 动作 | 载体 | 时长 | 谁来决定 |
|---|---|---|---|---|
| L1 | 观察（写 watch.txt，可查不可封） | EDL(watch) | 8 小时 | 自动 |
| L2 | 临时封禁 | DAG | 4 小时 | 自动 |
| L3 | 长期封禁 | DAG + EDL | 30 天 | 人工审批（默认） |
| L4 | 主机隔离 | KSC 任务/EDR | 按流程 | 人工 |

---

## 7. 白名单与防误封

### 7.1 四层模型

| 层 | 内容 | 维护者 | 是否可改 | 生效方式 |
|---|---|---|---|---|
| L0 | RFC1918、回环、CGNAT、组播、文档段、IPv6 ULA 等 20 个网段 | 代码内置 | 不可改 | 恒生效 |
| L1 | 出口 NAT 池、官网、邮件网关、VPN 池、DNS/代理、堡垒机、漏扫、专线对端 | 网络组 + 安全组 | 需审批 | 60 秒内热加载 |
| L2 | 厂商远程支持、临时测试机 | 值班工程师 | 需工单 | 即时，必须带 expire |
| L3 | 变更/演练时间窗（只观察不封禁） | 值班主管 | 需审批 | 定时生效 |

### 7.2 三处拦截

```
事件 → ①入库前过滤 → ②下发前复核 → ③PA 策略 negate 兜底
```

- ① 入库前：不产生记录，性能最好；
- ② 下发前：每次周期任务对"已封禁"IP 再判一次白名单，命中立即撤销并解封（**这一步最容易漏**）；
- ③ PA 侧：安全策略 `Source Negate = WL-All`，即使应用层写错也不会真的断业务。

### 7.3 加载期校验（会直接拒绝的写法）

| 写法 | 结果 |
|---|---|
| `0.0.0.0/0`、`/7` 及更宽 | 拒绝加载（防"手滑全放行"） |
| assets 缺 `why` | 拒绝加载 |
| temporary 缺 `expire` | 拒绝加载 |
| 网段格式非法（如 /33） | 拒绝加载 |
| 条目数比上次暴涨 3 倍以上 | 拒绝本次加载并告警（防误粘贴整份路由表） |

启动时校验失败 = 拒绝启动（fail-closed 于配置）；运行期热加载失败 = 保留旧配置 + 告警。

### 7.4 变更流程

1. 同事提 PR 或填单（改 `whitelist.yaml`）；
2. 网络组确认"这确实是我们单位地址"，安全组确认"为什么加"；
3. 合并后 60 秒内生效，或调用 `/api/whitelist/reload` 立即生效；
4. 临时项到期自动失效，提前 24 小时通知 owner；
5. 每次变更写审计（谁、何时、改了什么、工单号），保留 ≥ 6 个月。

### 7.5 六条硬规则

1. 内网源 IP 永不自动封禁（横向移动 → 主机隔离工单）；
2. 互联网出口 NAT 段必须整段进 L1（否则一封就是全单位断网）；
3. 域名/URL 类事件不转 IP 封禁（走 domain-sink）；
4. 云厂商/托管 IDC 段命中时降级为观察 + 告警；
5. 首次出现的 IP 只观察，达到阈值才升级；
6. 不做永久封禁，长期封禁必须经 L3 + 人工确认，且每日重算。

### 7.6 灰度与可观测

- `dry_run: true` 期间只记录"本来会封谁"，输出日报；
- 常驻指标：事件速率、解析失败率、白名单命中数、活跃封禁数、下发失败数、EDL 条目数；
- 灰度 1~2 周，业务方 + 网络组签字后再关闭 dry_run。

---

## 8. 部署实施

### 8.1 资源与网络

| 项 | 要求 |
|---|---|
| 主机 | 2 vCPU / 4 GB / 40 GB SSD（数千终端规模） |
| 系统 | Linux（Ubuntu 22.04 / RHEL 9 / 麒麟），Docker 24+ |
| 时间 | 必须与 KSC、PA 同源 NTP，否则审计时间无法对齐 |

| 源 → 目的 | 端口 | 用途 |
|---|---|---|
| KSC → 采集机 | 6514/TCP（TLS 可选） | syslog 推送 |
| 采集机 → PA（双机） | 443/TCP | User-ID API |
| PA → EDL 端点 | 443 或 80/TCP | 拉取 IP/域名清单 |
| 采集机 → KSC | 13299/TCP（可选） | OpenAPI 对账回补 |

### 8.2 部署步骤

1. 准备主机与目录：`/opt/ksc2pan`（程序）、`/data`（状态与 EDL）；
2. 导入镜像（离线：`docker save` / `load`）；
3. 复制 `config.yaml`、`whitelist.yaml`，**先填 L1 资产（尤其出口 NAT 段）**；
4. `cp .env.example .env`，保持 `KSC2PAN_DRY_RUN=true`、`PA_MODE=mock`；
5. `docker compose up -d`；
6. 打开 KSC syslog 导出（见 8.3）；
7. 用真实报文替换 `tools/samples/ksc_events.log` 并跑 `replay.py` 验证解析；
8. 改为 `PA_MODE=xmlapi` + 填 `PA_HOSTS` / `PA_API_KEY`，仍保持 dry_run；
9. 跑 `smoke.py` 与 PA 侧核对命令；
10. 灰度 → 关闭 dry_run。

### 8.3 KSC 配置

| 项 | 值 |
|---|---|
| 位置 | 管理服务器 → 事件 → 配置通知和事件导出 → 配置导出到 SIEM 系统 |
| 格式 | **Syslog（RFC 5424）** |
| 地址/端口 | 采集机 IP : 6514 |
| 协议 | TCP 或 TLS over TCP |
| 导出事件 | 策略 → 事件配置 → 勾选 → 属性 → "使用 Syslog 导出到 SIEM 系统" |
| 建议勾选 | 检测到网络攻击、检测到可疑网络活动、网络连接被阻止、Web 威胁（如需域名清单） |

> 注意：KSC for Windows 与 KSC Linux 的菜单路径略有差异，字段一致。

### 8.4 PA 配置

**(1) tag 与动态地址组**

```
Objects → Tags → 新建 KES-BLOCK
Objects → Address Groups → DG-KES-BLOCK，type=Dynamic，match="'KES-BLOCK'"
```

**(2) 安全策略**

| 字段 | 值 |
|---|---|
| 名称 | KES-BLOCK-IN |
| Source Zone | untrust |
| Source Address | DG-KES-BLOCK |
| Source Negate | WL-All（白名单地址组） |
| Destination Zone | trust |
| Action | Drop，Log at Session End |
| 位置 | 所有 inbound allow 规则之前 |

**(3) EDL 对象**

| 名称 | 类型 | 源 | 刷新 | 备注 |
|---|---|---|---|---|
| EDL-KES-IP | IP List | `http://<edl>:8081/ip-block.txt` | 5 分钟 | 引用到 Drop |
| EDL-KES-DOMAIN | Domain | `.../domain-sink.txt` | 每小时 | 配 Anti-Spyware sinkhole |
| EDL-KES-WATCH | IP List | `.../watch.txt` | 5 分钟 | 只观察，不引用到 Drop |

> 不配 Client Authentication。PAN-OS 认证失败会停止执行该列表（F7）。
> 容量：单型号 IP 条目上限 5 万，服务端默认 4 万条封顶，超限截断并告警。

**(4) API Key 与权限**

```
https://<fw>/api/?type=keygen&user=svc-ksc2pan&password=***
```

专用管理员仅授予 XML API 与 User-ID 权限；Key 只存 `.env` / secret，不入库不入日志。

**(5) HA**

- DAG：`PA_HOSTS` 填两台，逐台推送（代码已实现），否则主备切换后封禁丢失；
- EDL：两台各自拉同一 URL，无需额外配置。

### 8.5 关键配置项

| 文件 | 关键项 | 建议 |
|---|---|---|
| config.yaml | `service.dry_run` | 上线先 true |
| config.yaml | `policy.dag_ttl_seconds` | 4 小时起步，观察后再调 |
| config.yaml | `policy.observe_first` | 保持 true |
| config.yaml | `policy.require_approval_for_edl` | 保持 true（有审批流程后） |
| config.yaml | `paloalto.verify_tls` | 生产 true，实验室可 false |
| whitelist.yaml | `assets` | 先把出口 NAT 段补全，再开灰度 |
| vector.toml | `sources.ksc_syslog.address` | 0.0.0.0:6514，TLS 按需开启 |
| nginx/edl.conf | `allow/deny` | 只允许 PA 管理口 IP |

### 8.6 安全加固

- KSC2PAN 只监听内网，API 端口不对终端网段开放；
- 设置 `KSC2PAN_TOKEN` 后，写操作需带 token；
- EDL 端点只暴露 4 个固定文件，其余 403；
- 服务以非 root（uid 10001）运行；
- 审计表与原始事件保留 7 天（可调），可导出做取证。

---

## 9. 验证与验收

### 9.1 已完成的自动化验证

**(1) 单元/集成测试：36 个用例全部通过**

```
$ python -m pytest -q
....................................                                     [100%]
36 passed in 6.34s
```

覆盖：解析（8 例）、白名单（12 例）、服务与决策（11 例）、HTTP 接口（4 例）。

**(2) 冒烟自检：10 项全部通过（真实 uvicorn 实例）**

```
$ python tools/smoke.py --local
  [OK]   健康检查 /health
  [OK]   私网地址命中 L0 硬白名单
  [OK]   单位资产命中 L1 白名单
  [OK]   事件解析并给出判定：observe / 首次出现，先观察
  [OK]   第二次命中进入封禁：dag
  [OK]   封禁记录可查询
  [OK]   人工撤销
  [OK]   紧急熔断开启
  [OK]   紧急熔断关闭
  [OK]   Prometheus 指标可抓取
结果：10/10 通过
```

**(3) 样本回放：12 条事件，覆盖全部决策分支**

```
  #  事件类型                     终端     对端 IP         判定          说明
  1  GNRL_EV_ATTACK_DETECTED     PC-001  45.83.12.77    观察          首次出现，先观察
  2  GNRL_EV_ATTACK_DETECTED     PC-002  45.83.12.77    临时封禁(L2)   严重事件，立即临时封禁
  3  GNRL_EV_ATTACK_DETECTED     PC-003  45.83.12.77    待审批(L3)     命中阈值（3 台主机），待确认
  4  GNRL_EV_ATTACK_DETECTED     PC-004  222.128.16.5   白名单跳过     白名单 L1 命中：出口 NAT 池
  5  GNRL_EV_ATTACK_DETECTED     PC-005  10.20.30.40    内网源跳过     内网地址，转主机隔离工单
  6  GNRL_EV_WEB_URL_BLOCKED     PC-001  -              域名清单       加入 sinkhole，不做 IP 封禁
  7  GNRL_EV_VIRUS_FOUND         -       -              不适用         类别 file 不参与
  8  000007d1                    PC-007  103.145.22.19  观察          首次出现，先观察
  9  000007d1                    PC-008  103.145.22.19  临时封禁(L2)   24h 内第 2 次命中
 10  000007d1                    PC-009  103.145.22.19  待审批(L3)     命中阈值，待确认
 11  GNRL_EV_ATTACK_DETECTED     PC-010  185.220.101.42 观察          首次出现
 12  （脏数据）                  -       -              不适用         进 deadletter
```

产物：`ip-block.txt`（长期）、`watch.txt`（观察）、`domain-sink.txt`（域名）、
`whitelist.txt`（供 PA 白名单组同步）。

### 9.2 现场验收步骤

| 步骤 | 操作 | 期望结果 |
|---|---|---|
| 1 | 采集机 `tcpdump -A port 6514` | 能看到 `[event@11111 ...]` 报文 |
| 2 | `replay.py` 回放现场真实样本 | 每类事件都能取到正确对端 IP |
| 3 | 测试机 `nmap -sS` 扫描同网段主机 | KSC 出现"检测到网络攻击" |
| 4 | 观察 KSC2PAN `/api/blocks` | 出现该 IP，tier=L2 |
| 5 | PA 执行 `show object registered-ip all` | 出现该 IP，tag=KES-BLOCK，带过期秒数 |
| 6 | PA 流量日志 | 出现 drop，会话结束原因正确 |
| 7 | 把 TTL 临时改为 5 分钟后重测 | 到期自动消失，无需人工 |
| 8 | EDL 通道 | 文件更新后 5 分钟内 `request system external-list show` 可见 |

### 9.3 故障演练（上线前必做）

| 场景 | 操作 | 通过标准 |
|---|---|---|
| 采集中断 | 停 Vector 2 分钟 | 事件不丢（缓冲），恢复后补发 |
| 决策中断 | 停 KSC2PAN 5 分钟 | 已有封禁按 TTL 到期，无残留 |
| API 失败 | 改错 API Key | 告警 + 重试，不产生"假成功" |
| EDL 认证失败 | 给 EDL 加 Basic Auth 错误密码 | 监控能发现列表停止执行 |
| 服务重启 | 重启容器 | 未过期封禁自动重放 |
| 紧急止血 | `estop=true` | 1 分钟内停止下发，DAG 可清空 |

### 9.4 验收指标

| 指标 | 目标 |
|---|---|
| 事件 → 封禁时延（DAG） | P95 < 60 秒 |
| 解析准确率 | ≥ 99.5% |
| 灰度期误封导致业务中断 | 0 起 |
| 白名单判断正确率 | 100%（漏判即事故） |
| 服务可用性 | ≥ 99.5% |
| 审计完整性 | 每条封禁可追溯到原始事件 |

---

## 10. 运维手册

### 10.1 日常检查（每日 5 分钟）

1. `/health` 是否 ok，`dry_run` 状态是否符合预期；
2. `/stats` 中 `parse_errors` 是否突增（突增=KSC 侧格式或版本变化）；
3. 活跃封禁数是否异常（突增=可能被大范围扫描；突降=可能 EDL/API 故障）；
4. `mock_pa_dag.jsonl` 或 PA 侧 registered-ip 数量是否与实际一致；
5. 白名单 `last_error` 是否为空。

### 10.2 常见故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 有事件但无封禁 | 白名单命中 / 未达阈值 / 内网源 | 用 `/api/whitelist/check` 查判定依据 |
| 事件完全没进来 | KSC 未勾选导出 / 端口不通 / 事件码不在白名单 | 查 Vector 日志与 `tcpdump` |
| 事件类型全为空 | 报文格式变化 | 查 deadletter，补解析规则与用例 |
| PA 有记录但流量没被拦 | 策略顺序 / negate 白名单 / 方向写错 | 用 PA 的 Test Security Policy 验证 |
| 封禁到期不消失 | TTL 配置过大 / PA 时间不同步 | 检查 `expires` 与 NTP |
| EDL 不更新 | 认证失败 / 源不可达 / 缓存 | `show system external-list`；确认无 Basic Auth |
| 双机不同步 | 只推了一台 | 检查 `PA_HOSTS` 是否含两台 |

### 10.3 应急处置

**误封业务 IP**

```bash
curl -X POST "http://ksc2pan:8080/api/blocks/1.2.3.4/revoke?reason=误封&actor=张三"
# 同步把该段加入 whitelist.yaml，避免再次被封
```

**大面积误封（如 IDS 规则误报）**

```bash
curl -X POST "http://ksc2pan:8080/api/estop?on=true"     # 停止下发
# PA 侧如需立即全清：
#   clear object registered-ip all   （谨慎，会清掉所有 DAG 注册）
```

**回滚到上一版本**：保留上一版镜像 tag，`docker compose up -d` 指定即可；
数据库向后兼容（新增列自动迁移）。

### 10.4 备份

- 每日备份 `/data/ksc2pan.db`、`/data/edl/`、`config/whitelist.yaml`（后两者在 Git 中已有）；
- 保留 30 天；恢复时停服务 → 覆盖 → 启动（启动自动重放封禁）。

### 10.5 升级与解析回归

1. KSC/KES 升级前，导出 20 条真实样本；
2. 跑 `python -m pytest tests/test_parser.py`，失败即停；
3. 补齐新格式用例后再升级；
4. Vector 配置改动后执行 `vector validate`。

---

## 11. 风险与限制

| 编号 | 风险/限制 | 影响 | 概率 | 缓解 | 责任 |
|---|---|---|---|---|---|
| R1 | 端点视角盲区（不经终端的南北向扫描） | 漏封 | 高 | 补 PA Threat/Zone Protection 日志；二期接 PA 日志 | 安全组 |
| R2 | syslog 解析漂移（版本/语言变化） | 静默漏封 | 中 | 解析模块独立 + 回归用例 + deadletter 告警 | 开发 |
| R3 | syslog 丢包（UDP/断链） | 漏事件 | 中 | TCP/TLS + 磁盘缓冲 + OpenAPI 对账 | 运维 |
| R4 | 共享 IP/CDN 误封 | 业务中断 | 中 | 域名不转 IP + 云段复核 + TTL | 安全组 |
| R5 | 内网横向被当攻击源 | 封自己人 | 中 | 内网源永不自动封，转工单 | 安全组 |
| R6 | EDL fail-open | 以为在封其实没封 | 中 | 不配认证 + IP ACL + 拉取监控 | 运维 |
| R7 | EDL 容量超限 | 列表截断 | 低 | 4 万条封顶 + 超限告警 + 实时走 DAG | 运维 |
| R8 | DAG 非持久/HA 不同步 | 重启后封禁丢失 | 中 | 启动重放 + 逐台推送 + 一致性巡检 | 开发 |
| R9 | 无 SIEM 的取证短板 | 事后难回溯 | 中 | 原始事件留存 90 天 + 结构化疗审 | 安全组 |
| R10 | 自动化封禁的授权合规 | 审计质疑 | 中 | 书面授权 + 变更记录 + 双人审批 + 灰度报告 | 管理层 |
| R11 | 单点故障（采集/决策服务） | 封禁停止（存量按 TTL 到期） | 中 | 双实例 + 监控；安全侧可接受 | 运维 |
| R12 | PA API Key 泄露 | 越权操作 | 低 | 专用最小权限账号 + secret 管理 + 轮换 | 运维 |

**边界说明**：本方案是"端点情报驱动的边界封禁"，不替代 NDR/SIEM，也不承诺覆盖全部攻击面。
它的价值在于把已有检测能力转化为边界阻断，把"发现"变成"处置"。

---

## 12. 演进路线

| 阶段 | 内容 | 触发条件 |
|---|---|---|
| P5-1 | 接 PA 日志做"封禁前业务流量校验"（近 24h 有正常业务 → 降级观察） | 误封投诉 ≥ 2 次 |
| P5-2 | 接 KSC OpenAPI 对账通道，补齐 syslog 丢失 | 事件量 > 5000/日 |
| P5-3 | 引入 CrowdSec 作为多源决策前端（蜜罐/WAF/扫描器） | 出现第二个数据源 |
| P5-4 | 域名清单联动 DNS sinkhole + URL 过滤 | Web 威胁占比升高 |
| P5-5 | 若最终仍要上 SIEM：Vector 双写 Wazuh/Elastic，KSC2PAN 不变 | 合规或溯源要求 |

---

## 附录 A：API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /health | 健康检查 |
| POST | /ingest | 接收事件（单条/数组/NDJSON） |
| POST | /deadletter | 解析失败落库 |
| GET | /api/blocks?status=active\|pending\|expired\|revoked | 封禁列表 |
| POST | /api/blocks/{ip}/revoke | 撤销 |
| POST | /api/blocks/{ip}/approve | 待审批转长期 |
| GET | /api/whitelist | 白名单统计 |
| GET | /api/whitelist/check?ip= | 查询判定依据 |
| POST | /api/whitelist/reload | 热加载 |
| POST | /api/estop?on= | 熔断 |
| POST | /api/tick | 手工触发周期任务 |
| GET | /metrics | Prometheus |
| GET | /api/audit | 审计流水 |

## 附录 B：配置项全表

| 配置 | 默认 | 说明 |
|---|---|---|
| service.dry_run | true | 只记录不下发 |
| service.emergency_stop | false | 全局熔断 |
| policy.observe_first | true | 首次只观察 |
| policy.dag_ttl_seconds | 14400 | L2 时长 |
| policy.edl_ttl_days | 30 | L3 时长 |
| policy.dag_min_hits | 2 | L2 触发次数 |
| policy.critical_immediate | true | 严重事件免阈值 |
| policy.edl_min_hosts_10m | 3 | 升级主机数 |
| policy.edl_min_hits_24h | 10 | 升级次数 |
| policy.require_approval_for_edl | true | L3 需审批 |
| policy.block_inbound_only | true | 只封入站 |
| policy.max_blocks | 5000 | 活跃上限 |
| whitelist.min_v4_prefix | 8 | 拒绝更宽网段 |
| whitelist.max_growth_ratio | 3.0 | 条目暴涨保护 |
| paloalto.mode | mock | mock/xmlapi |
| paloalto.dag_tag | KES-BLOCK | 与 PA tag 一致 |
| paloalto.verify_tls | true | 证书校验 |
| edl.max_entries | 40000 | 单文件上限 |
| edl.aggregate | true | 聚合 CIDR |

## 附录 C：交付文件清单

| 路径 | 说明 |
|---|---|
| ksc2pan/README.md | 快速开始与运维命令 |
| ksc2pan/app/ksc2pan/*.py | 服务代码（7 个模块） |
| ksc2pan/app/Dockerfile | 镜像构建 |
| ksc2pan/config/config.yaml | 策略与连接配置 |
| ksc2pan/config/whitelist.yaml | 白名单模板 |
| ksc2pan/vector/vector.toml | 采集配置（含 VRL） |
| ksc2pan/nginx/edl.conf | EDL 端点 |
| ksc2pan/docker-compose.yml | 一键部署 |
| ksc2pan/tools/replay.py | 离线回放 |
| ksc2pan/tools/smoke.py | 部署自检 |
| ksc2pan/tools/md2docx.py | 本报告的 Markdown→Word 生成脚本 |
| ksc2pan/tools/samples/ksc_events.log | 样本 |
| ksc2pan/tests/ | 36 个用例 |

## 附录 D：参考链接

Kaspersky
- KSC 配置导出事件到 SIEM：https://support.kaspersky.com/KSC/14.2/zh-Hans/89277.htm
- 标记事件以 Syslog 导出：https://support.kaspersky.co.uk/ksc14/151325
- KSC Linux 事件导出：https://help.kaspersky.com/ksc-linux/16.1/151330
- KSC OpenAPI 事件过滤属性：https://support.kaspersky.com/ksc/13.2/kscapi/a00335.html
- KES 事件类型码：https://support.kaspersky.ru/kes12/246282

Palo Alto
- EDL 使用与限制：https://docs.paloaltonetworks.com （Objects → External Dynamic Lists）
- 各型号 EDL 容量（30 列表 / 5 万 IP / 最短 5 分钟）：
  https://docs.paloaltonetworks.com/vm-series/activation-and-onboarding/software-ngfw/
  maximum-limits-based-on-memory/maximum-limits-based-on-memory-11-2
- User-ID registered-ip 与 timeout：http://api-lab.paloaltonetworks.com/registered-ip.html
- pan-os-python userid 模块：https://pan-os-python.readthedocs.io/en/stable/module-userid.html

开源项目
- Vector：https://github.com/vectordotdev/vector
- pan-os-python：https://github.com/PaloAltoNetworks/pan-os-python
- CrowdSec：https://github.com/crowdsecurity/crowdsec
- cs-blocklist-mirror：https://github.com/crowdsecurity/cs-blocklist-mirror
- fail2ban：https://github.com/fail2ban/fail2ban
- KSC syslog decoder 参考（仅阅读）：https://github.com/tread-lightly/KSC_decoders_and_rules_for_Wazuh

---

（报告结束）

# KSC2PAN

把 **卡巴斯基 KSC / KES 的网络攻击事件**（网络威胁、可疑连接、攻击源 IP）自动转换成
**Palo Alto 防火墙的封禁动作**。不需要 SIEM，不需要商业组件，单机可跑。

> 配套文章：《告警在终端，封禁在边界 —— 一次 EDR 与防火墙的联动复盘》

```
KES 终端 ──► KSC ──Syslog/TLS──► Vector ──JSON──► KSC2PAN ──► DAG / EDL ──► PA Drop
                                                     │
                                              SQLite 审计 + whitelist.yaml
```

## 它解决什么

终端侧已经检出攻击，边界却毫不知情；值班同事手工查 IP、加地址对象、提交策略，十几分钟一次，
夜里无人处理。这个项目把这段链路自动化：秒级封禁、带 TTL 自动解封、白名单可自助维护、全链路可追溯。

## 四个设计取舍

| 决策 | 原因 |
|---|---|
| 实时封禁走 DAG，长期清单走 EDL | EDL 最短 5 分钟刷新、没有过期机制；DAG 的 `timeout` 支持 1 秒~30 天，秒级生效且免 commit |
| 首次出现只观察，第二次才封 | 避免 IDS 误报立刻断业务；攻击者通常重复，二次命中即封 |
| 内网源 IP 永不自动封 | 横向移动封 IP 等于封自己人，改为生成主机隔离工单 |
| 白名单三处拦截 | 入库前 + 下发前复核 + 防火墙 `negate` 兜底，最后一道不依赖本项目的代码正确性 |

## 快速开始（不接真实防火墙）

```bash
pip install -r app/requirements.txt

# 1) 回放样本，看清每条事件为什么封/不封
python tools/replay.py --file tools/samples/ksc_events.log --data-dir ./data-replay --reset

# 2) 起服务 + 冒烟自检（mock 模式）
python tools/smoke.py --local

# 3) 容器部署
cp .env.example .env      # 先保持 KSC2PAN_DRY_RUN=true
docker compose up -d --build
curl http://127.0.0.1:8080/health
```

期望输出（节选）：

```
  1  GNRL_EV_ATTACK_DETECTED  PC-001  45.83.12.77    观察          首次出现，先观察
  2  GNRL_EV_ATTACK_DETECTED  PC-002  45.83.12.77    临时封禁(L2)   严重事件，立即临时封禁
  3  GNRL_EV_ATTACK_DETECTED  PC-003  45.83.12.77    待审批(L3)     命中阈值，待人工确认
  4  GNRL_EV_ATTACK_DETECTED  PC-004  222.128.16.5   白名单跳过     白名单 L1 命中：出口 NAT 池
  5  GNRL_EV_ATTACK_DETECTED  PC-005  10.20.30.40    内网源跳过     内网地址，转主机隔离工单
```

## 目录

```
app/ksc2pan/
  ksc_parser.py     RFC5424 解析 + 事件分类 + 对端 IP 提取（三级策略）
  normalize.py      IP 归一化、L0 保留段、CIDR 聚合
  whitelist.py      四层白名单 + 加载期校验（防手滑）
  policy.py         决策：观察 / 封禁 / 升级 / 跳过（11 个出口）
  store.py          SQLite：事件计数、封禁状态、审计
  enforcer.py       PA XML API（含 HA 逐台推送）+ mock + EDL 原子写
  service.py        编排 + 周期任务（到期解封、白名单反查、EDL 刷新）
  main.py           FastAPI 路由
config/             策略阈值 + 白名单模板
vector/             syslog 采集与粗筛（VRL）
nginx/              EDL 端点
tools/              replay 回放 / smoke 自检 / md2docx / 样本
tests/              38 个用例
docs/               实施报告（md + docx）
```

## 测试

```bash
python -m pytest -q            # 38 passed
python tools/smoke.py --local  # 10/10
```

## 上线顺序（重要）

1. `whitelist.yaml` 先把 **L1 单位资产**补全，尤其是互联网出口 NAT 段；
   真实网段建议写到 `config/whitelist.local.yaml`（启动时自动追加合并，已在 `.gitignore` 中排除）；
2. 用真实报文替换 `tools/samples/ksc_events.log`，跑 `replay.py` 确认解析；
3. `PA_MODE=xmlapi` + 填 `PA_HOSTS` / `PA_API_KEY`，仍保持 `dry_run=true`；
4. 灰度 1~2 周，把 dry-run 日报给业务方与网络组看；
5. 签字后再关 `dry_run`。

## 免责声明

代码按"能跑、可读、可审计"的标准编写，并在模拟环境完成 38 项自动化测试与 10 项冒烟检查；
但**未在真实生产环境长期运行**。用于生产前请务必：先在 `dry_run` 下灰度、确认 KSC 事件格式与本项目的解析一致、
并核对 PA 安全策略顺序。自动化封禁属于高风险动作，请自行完成授权与变更评审。

## 许可

未附带开源许可证文件。如需商用或二次分发，请先与作者联系。

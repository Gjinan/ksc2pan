# 参与改进

这个项目是 MIT 许可、可自由修改与再分发的。欢迎直接开 issue 或提 PR ——
不管你是想支持更多 KES 版本、换一种执行面，还是把它接进自己的编排平台。

## 先跑起来

```bash
pip install -r app/requirements.txt
python -m pytest -q                 # 应输出 38 passed
python tools/smoke.py --local        # 应输出 10/10 通过
python tools/replay.py --file tools/samples/ksc_events.log --data-dir ./data-replay --reset
```

三条都不需要真实防火墙（默认 `PA_MODE=mock`、`dry_run=true`）。

## 最需要帮助的地方

| 方向 | 具体要做什么 |
|---|---|
| **KSC 事件格式** | 不同 KES 版本、不同界面语言（中/英/俄）的报文差异。**最有价值的贡献**：脱敏后把样本加进 `tools/samples/`，并在 `tests/test_parser.py` 补断言 |
| **事件码覆盖** | `app/ksc2pan/ksc_parser.py` 顶部的 `NETWORK_EVENTS` / `WEB_EVENTS` 是当前已知集合，缺的可以补 |
| **其他防火墙** | 目前只有 PAN-OS 的 User-ID API + EDL。FortiGate 的 Threat Feed、Check Point 的 IoC Feed 都能套同一套决策层，只需实现一个新的 `Enforcer` |
| **KSC OpenAPI 通道** | 现在用 syslog 实时通道，OpenAPI 只留了设计。可以做一条按时间窗回补的对账通道，解决丢事件问题 |
| **测试** | 决策分支的边缘场景、并发写入、大容量下的 EDL 生成 |

## 提 PR 前请确认

1. `python -m pytest -q` 全绿，新增逻辑要有对应用例；
2. 不引入新的重型依赖（当前只有 fastapi / uvicorn / pyyaml / requests）；
3. 默认值保持"安全侧"：能少封不多封，能观察不封禁；
4. **不要提交真实环境信息**：真实网段写 `config/whitelist.local.yaml`（已在 `.gitignore` 中），
   任何 token、内部域名、单位名称都不要进仓库；
5. 报文字段解析相关的改动，请同时给出样本，否则无法回归。

## 代码风格

- Python 3.12+，只用标准库 + 上面四个依赖；
- 中文注释，解释"为什么"而不是"做了什么"；
- 决策逻辑保持纯函数（`policy.py` 不产生副作用），副作用集中在 `service.py`；
- 每个"不封禁"的分支必须带可读的 `reason`，它会写进审计。

## 安全与合规

这是个自动化封禁工具，误封的代价是业务中断。所以：

- 任何默认值的改动，都要在 PR 里说明"为什么这样更安全"；
- 涉及白名单、阈值、TTL 的改动请附上推演过程（什么情况下会封、什么情况下不会）；
- 发现可能导致误封的缺陷，请按安全问题处理，先在 issue 里说明影响面。

## 许可

提交 PR 即表示你同意以 [MIT License](LICENSE) 授权你的贡献。

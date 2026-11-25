"""封禁决策：把"一条事件 + 一个 IP"映射成"一个动作"。

设计要点：
  · 这是纯函数式决策层（除了读取 store 里的历史计数），不产生副作用，
    便于单测覆盖所有分支；
  · 默认值一律偏保守：首次只观察、内网不封、只封入站、容量超限只观察；
  · 任何"不封"的结论都必须带可解释的 reason，写进审计。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .config import Config
from .ksc_parser import KscEvent
from .normalize import IPAddress, builtin_reason, classify
from .store import Store
from .whitelist import Whitelist

# 动作语义
IGNORE = "ignore"            # 不处理（不含 IP / 类别不适用）
INTERNAL = "internal"        # 内网源，转隔离工单
WHITELISTED = "whitelisted"  # 白名单命中，只审计
ESTOP = "estop"              # 紧急熔断
OBSERVE = "observe"          # 观察名单，不下发
DAG = "dag"                  # L2 临时封禁（带 TTL）
PENDING = "pending"          # L3 待人工确认
EDL = "edl"                  # L3 长期封禁
REFRESH = "refresh"          # 已封禁，仅续期/更新计数


@dataclass
class Decision:
    ip: str
    action: str
    tier: str = "NONE"
    reason: str = ""
    ttl: int = 0
    hits_24h: int = 0
    hosts_10m: int = 0
    whitelist: Optional[dict[str, Any]] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "action": self.action,
            "tier": self.tier,
            "reason": self.reason,
            "ttl": self.ttl,
            "hits_24h": self.hits_24h,
            "hosts_10m": self.hosts_10m,
            "whitelist": self.whitelist,
            **({"extra": self.extra} if self.extra else {}),
        }


class Policy:
    def __init__(self, cfg: Config, store: Store, whitelist: Whitelist):
        self.cfg = cfg
        self.store = store
        self.wl = whitelist

    # ------------------------------------------------------------------
    def decide(self, ev: KscEvent, ip: IPAddress, emergency_stop: bool = False) -> Decision:
        p = self.cfg.policy
        now = datetime.now(timezone.utc).timestamp()

        if emergency_stop or self.cfg.service.emergency_stop:
            return Decision(str(ip), ESTOP, reason="紧急熔断已开启，停止下发")

        # 1) 类别闸门：只有入站网络攻击源才进入封禁主流程
        if ev.category != "network_inbound":
            return Decision(str(ip), IGNORE, reason=f"事件类别 {ev.category} 不参与 IP 封禁")
        if p.block_inbound_only and ev.direction != "inbound":
            return Decision(str(ip), IGNORE, reason=f"方向 {ev.direction} 非入站，不封禁")

        # 2) 内网 / 保留段：永不自动封
        reason = builtin_reason(ip)
        if reason:
            return Decision(
                str(ip), INTERNAL, reason=f"内网/保留地址（{reason}），转主机隔离工单",
                extra={"suggestion": "isolate_host", "class": classify(ip)},
            )

        # 3) 白名单
        hit = self.wl.match(ip)
        if hit is not None:
            return Decision(str(ip), WHITELISTED, reason=f"白名单 {hit.layer} 命中：{hit.why}",
                            whitelist=hit.as_dict())

        # 4) 时间窗（变更/演练期只观察）
        win = self.wl.observe_only_now()
        if win is not None:
            return Decision(str(ip), OBSERVE, reason=f"时间窗 observe_only（{win.why or '未说明'}）")

        # 5) 历史计数
        hits_24h = self.store.count_hits(str(ip), now - 86400)
        hits_10m = self.store.count_hits(str(ip), now - 600)
        hosts_10m = self.store.count_hosts(str(ip), now - 600)
        existing = self.store.active_block(str(ip))

        # 6) 升级判定（先于"续期"判断，否则一旦进了 L2 就永远升不到 L3）
        escalate = hosts_10m >= p.edl_min_hosts_10m or hits_24h >= p.edl_min_hits_24h
        if escalate:
            if existing is not None and (existing["edl"] or existing["tier"] == "L3"):
                return Decision(
                    str(ip), REFRESH, tier="L3", reason="已在长期清单中，仅更新计数",
                    ttl=int(existing["expires"] - now), hits_24h=hits_24h, hosts_10m=hosts_10m,
                )
            if p.require_approval_for_edl:
                return Decision(
                    str(ip), PENDING, tier="L3", ttl=p.dag_ttl_seconds,
                    reason=f"命中阈值（10 分钟内 {hosts_10m} 台主机 / 24h {hits_24h} 次），"
                           "临时封禁保持，待人工确认是否转长期",
                    hits_24h=hits_24h, hosts_10m=hosts_10m,
                )
            return Decision(
                str(ip), EDL, tier="L3", ttl=p.edl_ttl_days * 86400,
                reason=f"命中阈值（10 分钟内 {hosts_10m} 台主机 / 24h {hits_24h} 次），加入长期清单",
                hits_24h=hits_24h, hosts_10m=hosts_10m,
            )

        # 7) 已封禁 → 续期/更新计数
        if existing is not None:
            return Decision(
                str(ip), REFRESH,
                tier=existing["tier"],
                reason="已在封禁中，仅更新计数",
                ttl=int(existing["expires"] - now),
                hits_24h=hits_24h, hosts_10m=hosts_10m,
            )

        # 8) 容量保护
        if self.store.count_active() >= p.max_blocks:
            return Decision(str(ip), OBSERVE, reason=f"活跃封禁数已达上限 {p.max_blocks}，仅观察",
                            hits_24h=hits_24h, hosts_10m=hosts_10m)

        # 9) 首次出现先观察：即便是 critical 也先看一眼，避免 IDS 误报立刻断业务；
        #    第二次命中时 critical 会跳过 dag_min_hits 直接封（见下一步）。
        critical = ev.severity == "critical"
        if p.observe_first and hits_10m <= 1:
            return Decision(str(ip), OBSERVE, reason="首次出现，先观察",
                            hits_24h=hits_24h, hosts_10m=hosts_10m)

        # 10) 严重事件不需要达到次数阈值，直接临时封禁
        if p.critical_immediate and critical:
            return Decision(str(ip), DAG, tier="L2", ttl=p.dag_ttl_seconds,
                            reason=f"严重事件 {ev.event_type}，立即临时封禁",
                            hits_24h=hits_24h, hosts_10m=hosts_10m)

        # 11) 达到基础阈值 → L2
        if hits_24h >= max(1, p.dag_min_hits):
            return Decision(str(ip), DAG, tier="L2", ttl=p.dag_ttl_seconds,
                            reason=f"24h 内第 {hits_24h} 次命中，临时封禁",
                            hits_24h=hits_24h, hosts_10m=hosts_10m)

        return Decision(str(ip), OBSERVE, reason="未达封禁阈值", hits_24h=hits_24h, hosts_10m=hosts_10m)

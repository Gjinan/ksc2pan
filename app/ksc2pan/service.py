"""编排层：事件 → 决策 → 执行 → 审计，以及后台的到期/对账/EDL 刷新。

API 与 tools/replay.py 都只调用这一层，保证"线上跑"和"回放测试"走同一套逻辑。
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from . import policy as P
from .config import Config, load_config
from .enforcer import BaseEnforcer, EdlWriter, PushResult, build_enforcer, retry
from .ksc_parser import KscEvent, parse_payload
from .normalize import IPAddress, parse_ip
from .policy import Decision, Policy
from .store import Store
from .whitelist import Whitelist

log = logging.getLogger("ksc2pan")


class Service:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.ensure_dirs()
        self.store = Store(cfg.db_path)
        self.whitelist = Whitelist(cfg.whitelist)
        self.whitelist.load(strict=False)
        self.policy = Policy(cfg, self.store, self.whitelist)
        self.enforcer: BaseEnforcer = build_enforcer(cfg)
        self.edl = EdlWriter(cfg)

        self.estop = bool(cfg.service.emergency_stop)
        self.metrics: Counter[str] = Counter()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_edl = 0.0
        self._last_tick = 0.0
        self._watch = self._load_state("watch.json", ttl=self.cfg.policy.dag_ttl_seconds * 2)
        self._domains = self._load_state("domains.json", ttl=self.cfg.policy.edl_ttl_days * 86400)

        if not self.whitelist.last_error:
            self._bootstrap()
        else:
            log.warning("白名单加载失败，按空白名单运行：%s", self.whitelist.last_error)

    # ------------------------------------------------------------------ 启动
    @classmethod
    def from_config(cls, path: str | None = None) -> "Service":
        return cls(load_config(path))

    def _bootstrap(self) -> None:
        """把未过期的封禁重放到 PA：registered-ip 非持久，重启必须重放。"""
        active = self.store.active_ips()
        if not active:
            return
        pairs = []
        for ip in active:
            row = self.store.get_block(ip) or {}
            ttl = int(max(60, row.get("expires", 0) - time.time()))
            pairs.append((ip, ttl))
        res = retry(lambda: self.enforcer.register_many(pairs), attempts=2)
        self.store.audit("system", "replay", "", {"count": len(pairs), "ok": res.ok, "detail": res.detail})
        log.info("启动重放 %s 条封禁，结果=%s", len(pairs), res.ok)

    def start(self) -> None:
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, name="ksc2pan-tick", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ 状态
    def _load_state(self, name: str, ttl: int) -> dict[str, float]:
        path = Path(self.cfg.service.data_dir) / name
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
        cutoff = time.time() - ttl
        return {k: float(v) for k, v in data.items() if float(v) >= cutoff}

    def _save_state(self, name: str, data: dict[str, float]) -> None:
        path = Path(self.cfg.service.data_dir) / name
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    # ------------------------------------------------------------------ 入口
    def process_payload(self, items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in items:
            try:
                ev = parse_payload(item)
                out.extend(self.process_event(ev, source=str(item.get("source") or "vector")))
            except Exception as exc:  # noqa: BLE001 - 单条失败不能影响整批
                self.metrics["process_errors"] += 1
                log.exception("处理事件失败：%s", exc)
                out.append({"ip": "", "action": "error", "reason": str(exc)})
        return out

    def process_event(self, ev: KscEvent, source: str = "vector") -> list[dict[str, Any]]:
        self.metrics["events_in"] += 1

        if ev.category == "web" and ev.urls:
            return [self._handle_domain(ev)]

        if ev.category != "network_inbound":
            self.metrics["ignored_category"] += 1
            return [{"ip": "", "action": P.IGNORE, "reason": f"类别 {ev.category} 不参与 IP 封禁"}]

        if not ev.remote_ip:
            self.metrics["no_ip"] += 1
            return [{"ip": "", "action": P.IGNORE, "reason": "未能从事件中提取到对端 IP"}]

        ip = parse_ip(ev.remote_ip)
        if ip is None:
            self.metrics["no_ip"] += 1
            return [{"ip": str(ev.remote_ip), "action": P.IGNORE, "reason": "IP 非法"}]

        self.store.record_event(
            ip=str(ip), host=ev.host_name, event_type=ev.event_type, severity=ev.severity,
            direction=ev.direction, source=source, raw=ev.raw or json.dumps(ev.fields, ensure_ascii=False),
            ts=ev.ts,
        )

        decision = self.policy.decide(ev, ip, emergency_stop=self.estop)
        return [self._apply(ev, ip, decision)]

    # ------------------------------------------------------------------ 执行
    def _apply(self, ev: KscEvent, ip: IPAddress, d: Decision, actor: str = "auto") -> dict[str, Any]:
        sip = str(ip)
        result = d.as_dict()
        result["event_type"] = ev.event_type
        result["host"] = ev.host_name

        if d.action == P.WHITELISTED:
            self.metrics["whitelist_hits"] += 1
            self.store.audit(actor, "whitelist_hit", sip, {"reason": d.reason, "wl": d.whitelist})
            result["applied"] = False
            return result

        if d.action == P.INTERNAL:
            self.metrics["internal_hits"] += 1
            self.store.audit(actor, "internal_source", sip, {"reason": d.reason, "host": ev.host_name})
            result["applied"] = False
            result["ticket"] = "需人工在 KSC 侧隔离该主机"
            return result

        if d.action == P.ESTOP:
            self.metrics["estop_skipped"] += 1
            result["applied"] = False
            return result

        if d.action == P.OBSERVE:
            with self._lock:
                self._watch[sip] = time.time()
            self.store.audit(actor, "observe", sip, {"reason": d.reason, "hosts": d.hosts_10m})
            self._maybe_refresh_edl(force=False)
            result["applied"] = False
            return result

        if d.action == P.REFRESH:
            self.store.touch_block(sip, d.hits_24h, d.hosts_10m)
            result["applied"] = False
            return result

        if d.action == P.PENDING:
            # 待审批期间保持临时封禁（TTL = dag_ttl），避免"等审批"变成"不封"
            res = retry(lambda: self.enforcer.register(sip, d.ttl), attempts=3)
            self.store.upsert_block(sip, "L3", d.reason, ev.event_type, d.hits_24h, d.hosts_10m,
                                    d.ttl, edl=False, action="pending", pending=True)
            self.store.mark_synced(sip, res.ok, "pending")
            self.store.audit(actor, "pending_approval", sip,
                             {"reason": d.reason, "ttl": d.ttl, "push_ok": res.ok})
            self.metrics["pending"] += 1
            result.update({"applied": res.ok, "ttl": d.ttl, "pending": True})
            return result

        if d.action in (P.DAG, P.EDL):
            return self._enforce(sip, d, ev, actor)

        result["applied"] = False
        return result

    def _enforce(self, sip: str, d: Decision, ev: KscEvent, actor: str) -> dict[str, Any]:
        want_edl = d.action == P.EDL
        ttl = int(d.ttl)
        res: PushResult = retry(lambda: self.enforcer.register(sip, ttl), attempts=3)
        row = self.store.upsert_block(
            sip, d.tier, d.reason, ev.event_type, d.hits_24h, d.hosts_10m, ttl,
            edl=want_edl, action=d.action,
        )
        self.store.mark_synced(sip, res.ok, d.action)
        self.store.audit(actor, d.action, sip, {
            "reason": d.reason, "ttl": ttl, "tier": d.tier, "push_ok": res.ok, "detail": res.detail,
        })
        self.metrics["blocks_created"] += 1
        if not res.ok:
            self.metrics["push_failures"] += 1
            log.error("DAG 下发失败 %s：%s", sip, res.detail)

        with self._lock:
            self._watch.pop(sip, None)
        if want_edl:
            self._maybe_refresh_edl(force=True)
        else:
            self._maybe_refresh_edl(force=False)

        return {
            "ip": sip, "action": d.action, "tier": d.tier, "reason": d.reason, "ttl": ttl,
            "hits_24h": d.hits_24h, "hosts_10m": d.hosts_10m,
            "event_type": ev.event_type, "host": ev.host_name,
            "applied": res.ok, "push": res.detail, "expires": row.get("expires"),
        }

    def _handle_domain(self, ev: KscEvent) -> dict[str, Any]:
        """恶意 URL/域名：不进 IP 封禁，写入域名清单（PA Domain EDL / DNS sinkhole）。"""
        hosts: list[str] = []
        for url in ev.urls:
            host = (urlparse(url).hostname or "").lower().strip(".")
            if host and not host.replace(".", "").isdigit():
                hosts.append(host)
        if not hosts:
            return {"ip": "", "action": P.IGNORE, "reason": "URL 无有效域名", "applied": False}
        with self._lock:
            for host in hosts:
                self._domains[host] = time.time()
        self.store.audit("auto", "domain_observe", "", {"domains": hosts, "host": ev.host_name,
                                                      "reason": "域名类事件不转 IP 封禁"})
        self._maybe_refresh_edl(force=True)
        return {"ip": "", "action": "domain", "tier": "NONE", "applied": False,
                "reason": "域名加入 sinkhole 清单，不做 IP 封禁", "domains": hosts,
                "event_type": ev.event_type, "host": ev.host_name}

    # ------------------------------------------------------------------ 人工操作
    def revoke(self, sip: str, actor: str, reason: str) -> dict[str, Any]:
        ip = parse_ip(sip)
        if ip is None:
            return {"ok": False, "detail": "IP 非法"}
        res = self.enforcer.unregister(str(ip))
        changed = self.store.revoke(str(ip), actor, reason)
        self.store.audit(actor, "revoke_push", str(ip), {"ok": res.ok, "detail": res.detail})
        self._maybe_refresh_edl(force=True)
        return {"ok": changed, "ip": str(ip), "push": res.detail}

    def approve(self, sip: str, actor: str) -> dict[str, Any]:
        """把"待审批"提升为 L3 长期封禁（EDL + 延长 TTL）。"""
        row = self.store.get_block(sip)
        if not row or not row.get("pending"):
            return {"ok": False, "detail": "该 IP 不在待审批状态"}
        ttl = self.cfg.policy.edl_ttl_days * 86400
        res = retry(lambda: self.enforcer.register(sip, ttl), attempts=2)
        self.store.upsert_block(sip, "L3", row["reason"] or "人工审批", row["event_type"] or "",
                                row["hits"], row["hosts"], ttl, edl=True, action="edl")
        self.store.mark_synced(sip, res.ok, "edl")
        self.store.audit(actor, "approve", sip, {"ttl": ttl, "push_ok": res.ok})
        self._maybe_refresh_edl(force=True)
        return {"ok": True, "ip": sip, "ttl": ttl}

    def set_estop(self, on: bool, actor: str) -> dict[str, Any]:
        self.estop = bool(on)
        self.store.audit(actor, "emergency_stop", "", {"on": self.estop})
        log.warning("紧急熔断：%s（操作人 %s）", self.estop, actor)
        return {"emergency_stop": self.estop}

    def reload_whitelist(self, actor: str = "api") -> dict[str, Any]:
        self.whitelist.load(strict=False)
        self.store.audit(actor, "whitelist_reload", "", self.whitelist.stats())
        return self.whitelist.stats()

    # ------------------------------------------------------------------ EDL
    def _maybe_refresh_edl(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_edl < 30:
            return
        self._last_edl = now
        self.refresh_edl()

    def refresh_edl(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            self._watch = {k: v for k, v in self._watch.items() if now - v < self.cfg.policy.dag_ttl_seconds * 2}
            self._domains = {k: v for k, v in self._domains.items() if now - v < self.cfg.policy.edl_ttl_days * 86400}
            watch = list(self._watch)
            domains = list(self._domains)

        stats = {
            "ip_block": self.edl.write("ip_block", self.store.active_ips(edl_only=True)),
            "watch": self.edl.write("watch", watch),
            "domain": self.edl.write("domain", domains),
            "whitelist": self.edl.write("whitelist", self.whitelist.export_cidrs()),
        }
        self._save_state("watch.json", self._watch)
        self._save_state("domains.json", self._domains)
        self.edl.write_manifest({"files": stats, "active_blocks": self.store.count_active()})
        return stats

    # ------------------------------------------------------------------ 周期任务
    def tick(self) -> dict[str, Any]:
        done: dict[str, Any] = {}
        expired = self.store.expire_due()
        for sip in expired:
            self.enforcer.unregister(sip)
            self.store.audit("system", "expired", sip, "TTL 到期，自动解封")
        done["expired"] = len(expired)

        # 白名单变更后复核：已封禁但现在是白名单的，立即撤销（第二处拦截）
        revoked = 0
        for row in self.store.list_blocks(status="active", limit=5000):
            ip = parse_ip(row["ip"])
            if ip is not None and self.whitelist.match(ip) is not None:
                self.revoke(row["ip"], "system", "白名单变更，自动撤销")
                revoked += 1
        done["whitelist_revoked"] = revoked

        changed = self.whitelist.reload_if_changed()
        done["whitelist_reloaded"] = changed
        done["edl"] = self.refresh_edl()
        done["pruned_events"] = self.store.prune_events(time.time() - 7 * 86400)
        done["stats"] = self.stats()
        return done

    def _loop(self) -> None:
        interval = 15
        while not self._stop.wait(interval):
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                log.exception("周期任务失败")
                self.metrics["tick_errors"] += 1

    # ------------------------------------------------------------------ 只读
    def stats(self) -> dict[str, Any]:
        return {
            "mode": {"dry_run": self.cfg.service.dry_run, "emergency_stop": self.estop,
                     "pa": self.enforcer.health()},
            "store": self.store.stats(),
            "whitelist": self.whitelist.stats(),
            "metrics": dict(self.metrics),
            "server_time": datetime.now(timezone.utc).isoformat(),
        }

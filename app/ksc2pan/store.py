"""SQLite 持久层：事件计数、封禁状态、审计。

选 SQLite 的理由：单机、零运维、可直接拷走做取证；封禁量级（万级）完全够用。
注意：DAG 注册是"运行态"，PA 重启会丢，所以 blocks 表是唯一可信的状态源，
服务启动时要按它重放。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  seen REAL NOT NULL,
  ip TEXT NOT NULL,
  host TEXT,
  event_type TEXT,
  severity TEXT,
  direction TEXT,
  source TEXT,
  raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip, seen);

CREATE TABLE IF NOT EXISTS blocks(
  ip TEXT PRIMARY KEY,
  tier TEXT NOT NULL,
  reason TEXT,
  event_type TEXT,
  hits INTEGER NOT NULL DEFAULT 0,
  hosts INTEGER NOT NULL DEFAULT 0,
  created REAL NOT NULL,
  expires REAL NOT NULL,
  status TEXT NOT NULL,
  dag_synced INTEGER NOT NULL DEFAULT 0,
  edl INTEGER NOT NULL DEFAULT 0,
  pending INTEGER NOT NULL DEFAULT 0,
  last_action TEXT,
  updated REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocks_status ON blocks(status);

CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  actor TEXT,
  action TEXT,
  ip TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"""


def now() -> float:
    return datetime.now(timezone.utc).timestamp()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            # 兼容 1.0 之前的库：补 seen 列（计数用"入库时间"，避免 KSC 补发历史事件时全部过期）
            cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            if "seen" not in cols:
                conn.execute("ALTER TABLE events ADD COLUMN seen REAL")
                conn.execute("UPDATE events SET seen=ts WHERE seen IS NULL")
            bcols = {row[1] for row in conn.execute("PRAGMA table_info(blocks)")}
            if "pending" not in bcols:
                conn.execute("ALTER TABLE blocks ADD COLUMN pending INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                yield conn
            finally:
                conn.close()

    # ------------------------------------------------------------ 事件
    def record_event(
        self,
        ip: str,
        host: str,
        event_type: str,
        severity: str,
        direction: str,
        source: str,
        raw: str,
        ts: Optional[float] = None,
    ) -> None:
        with self._conn() as conn:
            seen = now()
            conn.execute(
                "INSERT INTO events(ts, seen, ip, host, event_type, severity, direction, source, raw)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (ts or seen, seen, ip, host, event_type, severity, direction, source, raw[:4000]),
            )

    def count_hits(self, ip: str, since: float) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE ip=? AND seen>=?", (ip, since)
            ).fetchone()
            return int(row["c"])

    def count_hosts(self, ip: str, since: float) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT host) AS c FROM events WHERE ip=? AND seen>=? AND host<>''",
                (ip, since),
            ).fetchone()
            return int(row["c"])

    def prune_events(self, before: float) -> int:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM events WHERE seen<?", (before,))
            return cur.rowcount

    # ------------------------------------------------------------ 封禁
    def get_block(self, ip: str) -> Optional[dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM blocks WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else None

    def active_block(self, ip: str) -> Optional[dict[str, Any]]:
        row = self.get_block(ip)
        if row and row["status"] == "active" and row["expires"] > now():
            return row
        return None

    def upsert_block(
        self,
        ip: str,
        tier: str,
        reason: str,
        event_type: str,
        hits: int,
        hosts: int,
        ttl_seconds: int,
        edl: bool,
        action: str,
        pending: bool = False,
    ) -> dict[str, Any]:
        ts = now()
        expires = ts + max(60, ttl_seconds)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO blocks(ip, tier, reason, event_type, hits, hosts, created, expires,
                                   status, dag_synced, edl, pending, last_action, updated)
                VALUES(?,?,?,?,?,?,?,?,'active',0,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    tier=excluded.tier,
                    reason=excluded.reason,
                    event_type=excluded.event_type,
                    hits=excluded.hits,
                    hosts=excluded.hosts,
                    expires=excluded.expires,
                    status='active',
                    edl=MAX(blocks.edl, excluded.edl),
                    pending=excluded.pending,
                    last_action=excluded.last_action,
                    updated=excluded.updated
                """,
                (ip, tier, reason, event_type, hits, hosts, ts, expires,
                 1 if edl else 0, 1 if pending else 0, action, ts),
            )
        return self.get_block(ip) or {}

    def touch_block(self, ip: str, hits: int, hosts: int) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE blocks SET hits=?, hosts=?, updated=? WHERE ip=?", (hits, hosts, now(), ip)
            )

    def set_status(self, ip: str, status: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE blocks SET status=?, updated=? WHERE ip=?", (status, now(), ip)
            )
            return cur.rowcount > 0

    def mark_synced(self, ip: str, synced: bool, action: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE blocks SET dag_synced=?, last_action=?, updated=? WHERE ip=?",
                (1 if synced else 0, action, now(), ip),
            )

    def expire_due(self, at: Optional[float] = None) -> list[str]:
        """把到期封禁置为 expired，返回被处理的 IP。"""
        at = at or now()
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ip FROM blocks WHERE status='active' AND expires<=?", (at,)
            ).fetchall()
            ips = [r["ip"] for r in rows]
            if ips:
                conn.executemany(
                    "UPDATE blocks SET status='expired', updated=? WHERE ip=?",
                    [(at, ip) for ip in ips],
                )
            return ips

    def revoke(self, ip: str, actor: str, reason: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE blocks SET status='revoked', updated=? WHERE ip=? AND status='active'",
                (now(), ip),
            )
            changed = cur.rowcount > 0
        if changed:
            self.audit(actor, "revoke", ip, reason)
        return changed

    def list_blocks(self, status: str = "active", limit: int = 500) -> list[dict[str, Any]]:
        with self._conn() as conn:
            if status == "pending":
                rows = conn.execute(
                    "SELECT * FROM blocks WHERE pending=1 AND status='active' ORDER BY created DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM blocks WHERE status=? ORDER BY created DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            return [dict(r) for r in rows]

    def active_ips(self, edl_only: bool = False) -> list[str]:
        ts = now()
        sql = "SELECT ip FROM blocks WHERE status='active' AND expires>?"
        args: list[Any] = [ts]
        if edl_only:
            sql += " AND edl=1"
        with self._conn() as conn:
            return [r["ip"] for r in conn.execute(sql, args).fetchall()]

    def count_active(self) -> int:
        ts = now()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM blocks WHERE status='active' AND expires>?", (ts,)
            ).fetchone()
            return int(row["c"])

    # ------------------------------------------------------------ 审计
    def audit(self, actor: str, action: str, ip: str = "", detail: Any = "") -> None:
        if not isinstance(detail, str):
            detail = json.dumps(detail, ensure_ascii=False)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit(ts, actor, action, ip, detail) VALUES(?,?,?,?,?)",
                (now(), actor, action, ip, detail[:4000]),
            )

    def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            def one(sql: str, args: tuple[Any, ...] = ()) -> int:
                row = conn.execute(sql, args).fetchone()
                return int(row[0] or 0)

            day_ago = now() - 86400
            return {
                "events_total": one("SELECT COUNT(*) FROM events"),
                "events_24h": one("SELECT COUNT(*) FROM events WHERE ts>=?", (day_ago,)),
                "blocks_active": one(
                    "SELECT COUNT(*) FROM blocks WHERE status='active' AND expires>?", (now(),)
                ),
                "blocks_edl": one(
                    "SELECT COUNT(*) FROM blocks WHERE status='active' AND expires>? AND edl=1", (now(),)
                ),
                "blocks_expired": one("SELECT COUNT(*) FROM blocks WHERE status='expired'"),
                "blocks_revoked": one("SELECT COUNT(*) FROM blocks WHERE status='revoked'"),
                "audit_rows": one("SELECT COUNT(*) FROM audit"),
            }

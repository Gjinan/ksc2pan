"""执行层：把决策推给 Palo Alto。

两条通道：
  · DAG（User-ID API registered-ip）：带 timeout，秒级生效、到期自动解封 —— 实时封禁用；
  · EDL（纯文本文件，由 nginx 暴露）：防风墙拉取，长期清单用。
dry_run=True 时两个通道都只记录不落地，便于灰度。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import requests

from .config import Config
from .normalize import collapse_to_cidrs


@dataclass
class PushResult:
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "detail": self.detail}


def _uid_register(entries: list[tuple[str, int]], tag: str) -> str:
    body = "".join(
        f'<entry ip="{ip}"><tag><member timeout="{max(1, int(ttl))}">{tag}</member></tag></entry>'
        for ip, ttl in entries
    )
    return (
        "<uid-message><type>update</type><payload><register>"
        f"{body}"
        "</register></payload></uid-message>"
    )


def _uid_unregister(ips: Iterable[str], tag: str) -> str:
    body = "".join(f'<entry ip="{ip}"><tag><member>{tag}</member></tag></entry>' for ip in ips)
    return (
        "<uid-message><type>update</type><payload><unregister>"
        f"{body}"
        "</unregister></payload></uid-message>"
    )


class BaseEnforcer:
    def register(self, ip: str, ttl: int) -> PushResult:  # pragma: no cover - 接口
        raise NotImplementedError

    def register_many(self, entries: list[tuple[str, int]]) -> PushResult:
        for ip, ttl in entries:
            res = self.register(ip, ttl)
            if not res.ok:
                return res
        return PushResult(True, f"{len(entries)} 条")

    def unregister(self, ip: str) -> PushResult:  # pragma: no cover - 接口
        raise NotImplementedError

    def health(self) -> dict[str, object]:
        return {"mode": "base"}


class MockEnforcer(BaseEnforcer):
    """实验室/灰度用：把动作写进 JSONL，便于人工核对"本来会封谁"。"""

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, record: dict) -> None:
        record["ts"] = datetime.now(timezone.utc).isoformat()
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def register(self, ip: str, ttl: int) -> PushResult:
        self._write({"op": "register", "ip": ip, "ttl": ttl})
        return PushResult(True, "mock")

    def unregister(self, ip: str) -> PushResult:
        self._write({"op": "unregister", "ip": ip})
        return PushResult(True, "mock")

    def health(self) -> dict[str, object]:
        return {"mode": "mock", "log": str(self.log_path)}


class XmlApiEnforcer(BaseEnforcer):
    """PAN-OS XML API：type=user-id。

    HA 场景下 hosts 要填两台，逐台推送（registered-ip 不跨节点同步）。
    """

    def __init__(self, cfg: Config):
        pa = cfg.paloalto
        self.hosts = list(pa.hosts)
        self.api_key = pa.api_key
        self.tag = pa.dag_tag
        self.verify = pa.verify_tls
        self.timeout = pa.timeout
        if not self.hosts:
            raise ValueError("paloalto.hosts 为空")
        if not self.api_key:
            raise ValueError(f"未设置 API Key（环境变量 {pa.api_key_env}）")

    def _post(self, host: str, xml: str) -> PushResult:
        url = f"https://{host}/api/?type=user-id&key={self.api_key}"
        try:
            resp = requests.post(url, data={"uid": xml}, verify=self.verify, timeout=self.timeout)
        except requests.RequestException as exc:
            return PushResult(False, f"{host} 请求失败：{exc}")
        if resp.status_code != 200:
            return PushResult(False, f"{host} HTTP {resp.status_code}")
        text = resp.text or ""
        if 'status="success"' in text or "success" in text.lower():
            return PushResult(True, host)
        return PushResult(False, f"{host} 返回非成功：{text[:200]}")

    def _broadcast(self, xml: str) -> PushResult:
        results = [self._post(h, xml) for h in self.hosts]
        failed = [r.detail for r in results if not r.ok]
        if failed:
            return PushResult(False, "; ".join(failed))
        return PushResult(True, f"{len(self.hosts)} 台成功")

    def register(self, ip: str, ttl: int) -> PushResult:
        return self._broadcast(_uid_register([(ip, ttl)], self.tag))

    def register_many(self, entries: list[tuple[str, int]]) -> PushResult:
        if not entries:
            return PushResult(True, "0 条")
        # 分批，避免单个 XML 过大
        chunk = 200
        for i in range(0, len(entries), chunk):
            res = self._broadcast(_uid_register(entries[i : i + chunk], self.tag))
            if not res.ok:
                return res
        return PushResult(True, f"{len(entries)} 条")

    def unregister(self, ip: str) -> PushResult:
        return self._broadcast(_uid_unregister([ip], self.tag))

    def health(self) -> dict[str, object]:
        return {"mode": "xmlapi", "hosts": self.hosts, "tag": self.tag, "verify_tls": self.verify}


class EdlWriter:
    """原子写 EDL 文本：先写 .tmp 再 rename，避免防火墙拉到半截文件。"""

    FILES = {
        "ip_block": "ip-block.txt",
        "watch": "watch.txt",
        "domain": "domain-sink.txt",
        "whitelist": "whitelist.txt",
    }

    def __init__(self, cfg: Config):
        self.dir = Path(cfg.service.edl_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = cfg.edl.max_entries
        self.aggregate = cfg.edl.aggregate

    def write(self, kind: str, entries: Iterable[str]) -> dict[str, object]:
        name = self.FILES[kind]
        items = [str(e).strip() for e in entries if str(e).strip()]
        items = list(dict.fromkeys(items))
        truncated = False

        if kind in ("ip_block", "watch", "whitelist") and self.aggregate:
            items = collapse_to_cidrs(items)
        if len(items) > self.max_entries:
            items = items[: self.max_entries]
            truncated = True

        path = self.dir / name
        tmp = path.with_suffix(path.suffix + ".tmp")
        header = ""  # EDL 里不要写注释行，部分型号会当作条目
        tmp.write_text(header + "\n".join(items) + ("\n" if items else ""), encoding="utf-8")
        os.replace(tmp, path)
        return {"file": str(path), "entries": len(items), "truncated": truncated}

    def write_manifest(self, data: dict[str, object]) -> None:
        path = self.dir / "manifest.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), **data},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, path)


def build_enforcer(cfg: Config) -> BaseEnforcer:
    if cfg.service.dry_run or cfg.paloalto.mode == "mock":
        return MockEnforcer(Path(cfg.service.data_dir) / "mock_pa_dag.jsonl")
    if cfg.paloalto.mode == "xmlapi":
        return XmlApiEnforcer(cfg)
    raise ValueError(f"未知的 paloalto.mode：{cfg.paloalto.mode}")


def retry(fn, attempts: int = 3, base_delay: float = 1.0):
    """指数退避重试，用于 PA API 抖动。"""
    last: Optional[PushResult] = None
    for i in range(attempts):
        last = fn()
        if last.ok:
            return last
        if i < attempts - 1:
            time.sleep(base_delay * (2**i))
    return last or PushResult(False, "未执行")

"""四层白名单：L0 内置保留段 / L1 单位资产 / L2 临时例外 / L3 时间窗。

硬性规则：
  1. L0 不可被配置覆盖，也不可被"删除"，它直接来自 normalize.BUILTIN_RESERVED；
  2. L2 必须有 expire，过期自动失效；
  3. 加载时做合法性校验（网段过宽、必填字段缺失、条目暴涨），
     启动阶段校验失败 = 拒绝启动（fail-closed 于配置），运行期热加载失败 = 保留旧配置并告警。

本地覆盖：同目录下的 `whitelist.local.yaml` 会自动合并进来（追加，不覆盖），
用于"仓库里只放示例、现场真实网段放本地"的场景，该文件已在 .gitignore 中排除。
"""
from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from .config import WhitelistCfg
from .normalize import BUILTIN_RESERVED, IPAddress, builtin_reason, parse_ip

LOCAL_OVERRIDE_NAME = "whitelist.local.yaml"


class WhitelistError(ValueError):
    """白名单文件不合法。"""


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise WhitelistError(f"{path.name} 根节点必须是 mapping")
    return data


def _merge_layers(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """把本地覆盖文件里的条目追加到基础文件之后（同一套校验规则）。"""
    merged = dict(base)
    for key in ("assets", "temporary", "windows"):
        if extra.get(key):
            merged[key] = list(base.get(key) or []) + list(extra[key])
    return merged


@dataclass
class Entry:
    raw: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    why: str = ""
    owner: str = ""
    ticket: str = ""
    expire: Optional[float] = None

    @property
    def expired(self) -> bool:
        return self.expire is not None and self.expire <= datetime.now(timezone.utc).timestamp()


@dataclass
class Hit:
    layer: str
    network: str
    why: str
    ticket: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"layer": self.layer, "network": self.network, "why": self.why, "ticket": self.ticket}


@dataclass
class Window:
    start: float
    end: float
    mode: str
    why: str


@dataclass
class Snapshot:
    assets: list[Entry] = field(default_factory=list)
    temporary: list[Entry] = field(default_factory=list)
    windows: list[Window] = field(default_factory=list)
    loaded_at: float = 0.0
    mtime: float = 0.0
    version: str = ""
    warnings: list[str] = field(default_factory=list)


def _ts(value: Any, what: str) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value or "").strip()
    if not s:
        raise WhitelistError(f"{what} 不能为空")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise WhitelistError(f"{what} 不是合法的 ISO 时间：{value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class Whitelist:
    def __init__(self, cfg: WhitelistCfg):
        self.cfg = cfg
        self._lock = threading.RLock()
        self._snap = Snapshot()
        self._path = Path(cfg.path)
        self.last_error: str = ""

    # ------------------------------------------------------------ 加载/校验
    @property
    def local_path(self) -> Path:
        """同目录下的本地覆盖文件（现场真实网段，不进 Git）。"""
        return self._path.parent / LOCAL_OVERRIDE_NAME

    def load(self, strict: bool = True) -> None:
        """strict=True：任何校验失败都抛异常（启动阶段用）。"""
        with self._lock:
            if not self._path.exists():
                if strict:
                    raise WhitelistError(f"白名单文件不存在：{self._path}")
                self.last_error = "whitelist file missing"
                return
            mtime = self._path.stat().st_mtime
            if self.local_path.exists():
                mtime = max(mtime, self.local_path.stat().st_mtime)
            try:
                data = _load_yaml(self._path)
                if self.local_path.exists():
                    data = _merge_layers(data, _load_yaml(self.local_path))
                snap = self._build(data, mtime)
            except Exception as exc:  # noqa: BLE001 - 统一转成白名单错误
                self.last_error = str(exc)
                if strict:
                    raise WhitelistError(str(exc)) from exc
                return

            prev = self._snap
            if prev.assets and len(snap.assets) > max(1, len(prev.assets)) * self.cfg.max_growth_ratio:
                msg = (
                    f"白名单条目数异常增长：{len(prev.assets)} → {len(snap.assets)}，"
                    f"超过 {self.cfg.max_growth_ratio} 倍阈值，已拒绝本次加载"
                )
                self.last_error = msg
                if strict:
                    raise WhitelistError(msg)
                return

            self._snap = snap
            self.last_error = ""

    def reload_if_changed(self) -> bool:
        """文件 mtime 变化则热加载；失败保留旧快照。"""
        with self._lock:
            if not self._path.exists():
                return False
            try:
                mtime = self._path.stat().st_mtime
            except OSError:
                return False
            if mtime <= self._snap.mtime:
                return False
            self.load(strict=False)
            return self.last_error == ""

    def _build(self, data: dict[str, Any], mtime: float) -> Snapshot:
        if not isinstance(data, dict):
            raise WhitelistError("白名单根节点必须是 mapping")

        warns: list[str] = []
        assets: list[Entry] = []
        temporary: list[Entry] = []

        for idx, item in enumerate(data.get("assets") or []):
            entry = self._entry(item, f"assets[{idx}]", require_expire=False)
            if entry.why == "":
                raise WhitelistError(f"assets[{idx}] 缺少 why（必须说明为什么不能封）")
            if entry.owner == "":
                warns.append(f"assets[{idx}] 缺少 owner")
            assets.append(entry)

        for idx, item in enumerate(data.get("temporary") or []):
            entry = self._entry(item, f"temporary[{idx}]", require_expire=True)
            if entry.expired:
                warns.append(f"temporary[{idx}] {entry.raw} 已过期，已忽略")
                continue
            if not entry.ticket:
                warns.append(f"temporary[{idx}] 缺少 ticket（建议填写工单号）")
            temporary.append(entry)

        windows: list[Window] = []
        for idx, item in enumerate(data.get("windows") or []):
            start = _ts(item.get("start"), f"windows[{idx}].start")
            end = _ts(item.get("end"), f"windows[{idx}].end")
            if end <= start:
                raise WhitelistError(f"windows[{idx}] end 必须晚于 start")
            windows.append(
                Window(start=start, end=end, mode=str(item.get("mode") or "observe_only"), why=str(item.get("why") or ""))
            )

        # L0 与 L1 重叠时提示（多半是同事把内网段又写了一遍）
        builtin_nets = [(ipaddress.ip_network(n), label) for n, label in BUILTIN_RESERVED]
        for entry in assets:
            for net, label in builtin_nets:
                if entry.network.version == net.version and entry.network.subnet_of(net):
                    warns.append(f"{entry.raw} 完全落在 L0 保留段（{label}）内，属于冗余配置")
                    break

        assets.sort(key=lambda e: e.network.prefixlen, reverse=True)
        temporary.sort(key=lambda e: e.network.prefixlen, reverse=True)

        return Snapshot(
            assets=assets,
            temporary=temporary,
            windows=windows,
            loaded_at=datetime.now(timezone.utc).timestamp(),
            mtime=mtime,
            version=str(data.get("version") or ""),
            warnings=warns,
        )

    def _entry(self, item: Any, where: str, require_expire: bool) -> Entry:
        if isinstance(item, str):
            item = {"cidr": item}
        if not isinstance(item, dict):
            raise WhitelistError(f"{where} 必须是字符串或 mapping")
        raw = str(item.get("cidr") or item.get("ip") or "").strip()
        if not raw:
            raise WhitelistError(f"{where} 缺少 cidr")

        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise WhitelistError(f"{where} 网段不合法：{raw}") from exc

        min_prefix = self.cfg.min_v4_prefix if network.version == 4 else self.cfg.min_v6_prefix
        if network.prefixlen < min_prefix:
            raise WhitelistError(
                f"{where} {raw} 过宽（/{network.prefixlen} < 允许的 /{min_prefix}），"
                "这会把整片公网纳入白名单"
            )

        expire = None
        if item.get("expire"):
            expire = _ts(item["expire"], f"{where}.expire")
        elif require_expire:
            raise WhitelistError(f"{where} {raw} 是临时例外，必须填写 expire")

        return Entry(
            raw=raw,
            network=network,
            why=str(item.get("why") or ""),
            owner=str(item.get("owner") or ""),
            ticket=str(item.get("ticket") or ""),
            expire=expire,
        )

    # ------------------------------------------------------------ 查询
    def match(self, ip: IPAddress) -> Optional[Hit]:
        """按 L0 → L1 → L2 顺序匹配，返回第一个命中的层。"""
        with self._lock:
            reason = builtin_reason(ip)
            if reason:
                return Hit(layer="L0", network=reason, why="内置保留段")

            for entry in self._snap.assets:
                if ip.version == entry.network.version and ip in entry.network:
                    return Hit(
                        layer="L1",
                        network=str(entry.network),
                        why=entry.why or "单位资产",
                        ticket=entry.ticket,
                    )
            for entry in self._snap.temporary:
                if entry.expired:
                    continue
                if ip.version == entry.network.version and ip in entry.network:
                    return Hit(
                        layer="L2",
                        network=str(entry.network),
                        why=entry.why or "临时例外",
                        ticket=entry.ticket,
                    )
            return None

    def observe_only_now(self) -> Optional[Window]:
        """当前是否处于"只观察不封禁"的时间窗。"""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            for win in self._snap.windows:
                if win.start <= now <= win.end and win.mode == "observe_only":
                    return win
        return None

    def export_cidrs(self) -> list[str]:
        """导出给 PA `WL-All` 地址组 / 白名单 EDL 使用（不含 L0，L0 不该出现在公网策略里）。"""
        with self._lock:
            out = {str(e.network) for e in self._snap.assets}
            out |= {str(e.network) for e in self._snap.temporary if not e.expired}
            return sorted(out)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "path": str(self._path),
                "local_override": str(self.local_path) if self.local_path.exists() else "",
                "version": self._snap.version,
                "assets": len(self._snap.assets),
                "temporary": len(self._snap.temporary),
                "windows": len(self._snap.windows),
                "loaded_at": self._snap.loaded_at,
                "warnings": self._snap.warnings,
                "last_error": self.last_error,
            }

    def check(self, value: str) -> dict[str, Any]:
        ip = parse_ip(value)
        if ip is None:
            return {"input": value, "valid": False, "reason": "不是合法 IP"}
        hit = self.match(ip)
        return {
            "input": value,
            "ip": str(ip),
            "valid": True,
            "whitelisted": hit is not None,
            "hit": hit.as_dict() if hit else None,
            "observe_only_now": self.observe_only_now() is not None,
        }

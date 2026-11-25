"""配置加载与默认值。

约定：所有"可能被现场改"的开关都在 config.yaml；所有"策略阈值"都有安全默认值
（宁可少封，不可多封）。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ServiceCfg:
    data_dir: str = "/data"
    edl_dir: str = "/data/edl"
    dry_run: bool = True
    emergency_stop: bool = False
    log_level: str = "INFO"


@dataclass
class PolicyCfg:
    observe_first: bool = True          # 首次出现只观察
    dag_ttl_seconds: int = 4 * 3600     # L2 临时封禁时长
    edl_ttl_days: int = 30              # L3 长期封禁天数
    dag_min_hits: int = 2               # 达到几次才 DAG
    critical_immediate: bool = True     # critical 事件立即 DAG，绕过阈值
    edl_min_hits_24h: int = 10
    edl_min_hosts_10m: int = 3
    require_approval_for_edl: bool = True
    block_inbound_only: bool = True
    max_blocks: int = 5000              # 活跃封禁上限，超过只观察并告警


@dataclass
class WhitelistCfg:
    path: str = "/etc/ksc2pan/whitelist.yaml"
    reload_interval: int = 60
    min_v4_prefix: int = 8              # 拒绝比 /8 更宽的 IPv4 段
    min_v6_prefix: int = 16
    max_growth_ratio: float = 3.0       # 条目数暴涨视为误操作


@dataclass
class PaloAltoCfg:
    mode: str = "mock"                  # mock | xmlapi
    hosts: list[str] = field(default_factory=list)
    api_key_env: str = "PA_API_KEY"
    vsys: str = "vsys1"
    dag_tag: str = "KES-BLOCK"
    verify_tls: bool = True
    timeout: int = 10

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "")


@dataclass
class EdlCfg:
    max_entries: int = 40000            # 防火墙单型号上限 50k，留余量
    aggregate: bool = True              # 聚合为 CIDR


@dataclass
class NotifyCfg:
    webhook: str = ""
    min_level: str = "L3"


@dataclass
class Config:
    service: ServiceCfg = field(default_factory=ServiceCfg)
    policy: PolicyCfg = field(default_factory=PolicyCfg)
    whitelist: WhitelistCfg = field(default_factory=WhitelistCfg)
    paloalto: PaloAltoCfg = field(default_factory=PaloAltoCfg)
    edl: EdlCfg = field(default_factory=EdlCfg)
    notify: NotifyCfg = field(default_factory=NotifyCfg)
    source_path: str = ""

    @property
    def db_path(self) -> Path:
        return Path(self.service.data_dir) / "ksc2pan.db"

    @property
    def edl_path(self) -> Path:
        p = Path(self.service.edl_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def ensure_dirs(self) -> None:
        Path(self.service.data_dir).mkdir(parents=True, exist_ok=True)
        self.edl_path.mkdir(parents=True, exist_ok=True)


def _fill(obj: Any, data: dict[str, Any]) -> Any:
    known = {f.name: f for f in fields(obj)}
    for key, value in (data or {}).items():
        if key in known and value is not None:
            setattr(obj, key, value)
    return obj


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """加载 YAML；文件不存在时用默认值（默认 dry_run=True，安全侧）。"""
    cfg = Config()
    if path is None:
        path = os.environ.get("KSC2PAN_CONFIG", "config/config.yaml")
    p = Path(path)
    if not p.exists():
        cfg.ensure_dirs()
        return cfg

    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    for section in ("service", "policy", "whitelist", "paloalto", "edl", "notify"):
        if section in data and isinstance(data[section], dict):
            _fill(getattr(cfg, section), data[section])
    cfg.source_path = str(p)

    # 环境变量覆盖（容器部署时更省事）
    if os.environ.get("KSC2PAN_DRY_RUN") is not None:
        cfg.service.dry_run = os.environ["KSC2PAN_DRY_RUN"].lower() in ("1", "true", "yes")
    if os.environ.get("PA_HOSTS"):
        cfg.paloalto.hosts = [h.strip() for h in os.environ["PA_HOSTS"].split(",") if h.strip()]
    if os.environ.get("PA_MODE"):
        cfg.paloalto.mode = os.environ["PA_MODE"]
    if os.environ.get("KSC2PAN_DATA_DIR"):
        base = os.environ["KSC2PAN_DATA_DIR"]
        cfg.service.data_dir = base
        cfg.service.edl_dir = os.path.join(base, "edl")
    if os.environ.get("KSC2PAN_WHITELIST"):
        cfg.whitelist.path = os.environ["KSC2PAN_WHITELIST"]

    cfg.ensure_dirs()
    return cfg

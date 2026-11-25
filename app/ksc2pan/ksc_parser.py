"""KSC → Syslog(RFC5424) 事件解析。

这套逻辑与 vector/vector.toml 里的 VRL 是同一份规则的两种实现，
修改任何一侧都必须同步另一侧，并且跑 tests/test_parser.py 做回归。

报文形态（实测样例，字段随 KES 版本/语言变化）：
<134>1 2024-02-19T13:18:51.000Z EXAMPLE-PC KES|11.0.0.0 - GNRL_EV_ATTACK_DETECTED \
[event@11111 p1="..." et="GNRL_EV_ATTACK_DETECTED" tdn="Intrusion Prevention" \
 hdn="EXAMPLE-PC" hip="10.10.10.10" gn="Managed devices"] \
 结果: 已阻止\r\n远程 IP 地址: 203.0.113.9\r\n协议: TCP
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .normalize import extract_ipv4_candidates, parse_ip

# ------------------------------------------------------------------ 事件分类
# 参考 KES 12 事件码表 + KSC syslog decoder 社区实践，可按现场补齐。
NETWORK_EVENTS = {
    "GNRL_EV_ATTACK_DETECTED",  # 检测到网络攻击
    "000007d1",                 # 检测到可疑网络活动
    "00000329",                 # 网络活动被禁止 / 网络连接被阻止
    "00000abe",                 # 网络连接被阻止
}
WEB_EVENTS = {
    "GNRL_EV_WEB_URL_BLOCKED",
    "GNRL_EV_WEB_URL_BLOCKED_BY_KSN",
    "GNRL_EV_WEB_URL_WARNING",
    "GNRL_EV_VIRUS_FOUND_AND_REPORTED",  # 打开了危险链接
    "GNRL_EV_VIRUS_FOUND_AND_PASSED",
}
FILE_EVENTS = {
    "GNRL_EV_VIRUS_FOUND",
    "GNRL_EV_OBJECT_BLOCKED",
    "GNRL_EV_OBJECT_CURED",
    "GNRL_EV_OBJECT_DELETED",
    "GNRL_EV_OBJECT_NOTCURED",
    "GNRL_EV_SUSPICIOUS_OBJECT_FOUND",
}
CRITICAL_EVENTS = {"GNRL_EV_ATTACK_DETECTED", "000000e7"}

SEVERITY_BY_EVENT = {
    "GNRL_EV_ATTACK_DETECTED": "critical",
    "000007d1": "high",
    "00000329": "medium",
    "00000abe": "medium",
    "GNRL_EV_WEB_URL_BLOCKED": "high",
    "GNRL_EV_WEB_URL_BLOCKED_BY_KSN": "high",
    "GNRL_EV_VIRUS_FOUND_AND_REPORTED": "high",
}

# 正文里"对端/攻击源"字段的多语言标签（KES 中文/英文/俄文界面）
# 注意：中文常见写法有"远程 IP 地址""远程IP地址"，英文有"Remote IP address"，
# 因此每个标签都允许"IP + 可选的地址/address"后缀。
_REMOTE_LABELS = (
    r"远程\s*(?:IP|地址)(?:\s*地址)?",
    r"攻击者\s*(?:IP|地址)?",
    r"攻击源\s*(?:IP|地址)?",
    r"源\s*(?:IP|地址)(?:\s*地址)?",
    r"对端\s*(?:IP|地址)?",
    r"Remote\s*(?:IP|address)(?:\s*address)?",
    r"Source\s*(?:IP|address)(?:\s*address)?",
    r"Attacker\s*(?:IP|address)?",
    r"ИП-адрес\s*источника",
    r"IP-адрес\s*источника",
    r"Удаленный\s*(?:IP|адрес)",
)
_REMOTE_RE = re.compile(
    r"(?:" + "|".join(_REMOTE_LABELS) + r")\s*[:：=]\s*"
    r"((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))",
    re.IGNORECASE,
)
# 结构化字段里可能承载对端 IP 的键（按优先级）
_REMOTE_KEYS = (
    "src_ip", "srcip", "source_ip", "remote_ip", "remoteip", "peer_ip",
    "net_src_ip", "netsrcip", "attacker_ip", "external_ip", "dst_ip",
)
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
_SD_RE = re.compile(r"\[event@(?P<sd_id>\d+)\s(?P<kv>.*?)\](?P<body>.*)$", re.DOTALL)
_KV_RE = re.compile(r"([A-Za-z_][\w.\-]*)=\"((?:[^\"\\]|\\.)*)\"")
_SYSLOG_RE = re.compile(
    r"^(?:<\d{1,3}>)?1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)


@dataclass
class KscEvent:
    """归一化后的单条 KSC 事件。"""

    raw: str
    ts: float
    host_name: str = ""
    app: str = ""
    event_type: str = ""
    agent_ip: Optional[str] = None
    group: str = ""
    category: str = "other"
    severity: str = "low"
    direction: str = "unknown"
    remote_ip: Optional[str] = None
    remote_ips: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    body: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_blockable_category(self) -> bool:
        """只有"入站攻击源"才进入自动封禁主流程。"""
        return self.category == "network_inbound" and self.direction == "inbound"


def _parse_ts(value: str) -> float:
    s = (value or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    for parser in (
        lambda x: datetime.fromisoformat(x),
        lambda x: datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%f%z"),
        lambda x: datetime.strptime(x, "%Y-%m-%dT%H:%M:%S%z"),
    ):
        try:
            dt = parser(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            continue
    return datetime.now(tz=timezone.utc).timestamp()


def _classify(event_type: str, urls: list[str], body: str) -> str:
    et = (event_type or "").strip()
    if et in NETWORK_EVENTS:
        return "network_inbound"
    if et in WEB_EVENTS:
        return "web"
    if et in FILE_EVENTS:
        # 文件类事件若带 URL（下载被拦），归到 web 以便走域名通道
        return "web" if urls else "file"
    if et.startswith("0000"):  # 未知的数字事件码
        return "other"
    return "other"


def _direction(category: str, fields: dict[str, str], body: str) -> str:
    blob = " ".join([body, " ".join(f"{k}={v}" for k, v in fields.items())]).lower()
    if "inbound" in blob or "入站" in blob or "incoming" in blob:
        return "inbound"
    if "outbound" in blob or "出站" in blob or "outgoing" in blob:
        return "outbound"
    if category == "network_inbound":
        return "inbound"
    if category == "web":
        return "outbound"
    return "unknown"


def _pick_remote_ip(
    fields: dict[str, str], body: str, agent_ip: Optional[str]
) -> tuple[Optional[str], list[str]]:
    """按"结构化字段 → 带标签正文 → 全文兜底"三级策略取对端 IP。"""
    for key in _REMOTE_KEYS:
        ip = parse_ip(fields.get(key))
        if ip is not None:
            return str(ip), [str(ip)]

    m = _REMOTE_RE.search(body or "")
    if m:
        ip = parse_ip(m.group(1))
        if ip is not None:
            return str(ip), [str(ip)]

    candidates = extract_ipv4_candidates(body or "")
    filtered: list[str] = []
    for cand in candidates:
        ip = parse_ip(cand)
        if ip is None or not ip.is_global:
            continue
        if agent_ip and str(ip) == agent_ip:
            continue
        filtered.append(str(ip))
    if filtered:
        return filtered[0], filtered
    return None, []


def parse_line(raw: str) -> KscEvent:
    """解析一行 KSC syslog 报文。解析失败时返回 category=other 的事件，绝不抛异常。"""
    raw = (raw or "").strip()
    fields: dict[str, str] = {}
    body = raw
    host_name = ""
    app = ""
    ts = datetime.now(tz=timezone.utc).timestamp()

    m_head = _SYSLOG_RE.match(raw)
    if m_head:
        ts = _parse_ts(m_head.group("ts"))
        host_name = "" if m_head.group("host") in ("-", "") else m_head.group("host")
        app = "" if m_head.group("app") in ("-", "") else m_head.group("app")
        body = m_head.group("rest")

    m_sd = _SD_RE.search(body)
    if m_sd:
        for k, v in _KV_RE.findall(m_sd.group("kv")):
            fields[k] = v.replace('\\"', '"').replace("\\\\", "\\")
        body = m_sd.group("body")

    event_type = fields.get("et") or fields.get("event_type") or ""
    if not event_type:
        m_et = re.search(r"\b(GNRL_EV_[A-Z0-9_]+)\b", raw)
        if m_et:
            event_type = m_et.group(1)

    agent_ip = None
    for key in ("hip", "host_ip", "agent_ip", "HostIp"):
        parsed = parse_ip(fields.get(key))
        if parsed is not None:
            agent_ip = str(parsed)
            break

    host_name = host_name or fields.get("hdn", "")
    urls = [u.rstrip(".,;)") for u in _URL_RE.findall(body)] + [
        u.rstrip(".,;)") for u in _URL_RE.findall(raw)
    ]
    urls = list(dict.fromkeys(urls))

    category = _classify(event_type, urls, body)
    remote_ip, remote_ips = _pick_remote_ip(fields, body, agent_ip)

    return KscEvent(
        raw=raw,
        ts=ts,
        host_name=host_name,
        app=app,
        event_type=event_type,
        agent_ip=agent_ip,
        group=fields.get("gn", ""),
        category=category,
        severity=SEVERITY_BY_EVENT.get(event_type, "low"),
        direction=_direction(category, fields, body),
        remote_ip=remote_ip,
        remote_ips=remote_ips,
        urls=urls,
        body=body.strip(),
        fields=fields,
    )


def parse_payload(item: dict[str, Any]) -> KscEvent:
    """兼容两种输入：Vector 发来的结构化字段，或原始报文。

    结构化优先，但一律再过一遍 parse_line 做兜底取值。
    """
    raw = str(item.get("raw") or item.get("message") or "")
    ev = parse_line(raw) if raw else KscEvent(raw="", ts=datetime.now(tz=timezone.utc).timestamp())

    if item.get("event_type"):
        ev.event_type = str(item["event_type"])
        ev.category = _classify(ev.event_type, ev.urls, ev.body)
    if item.get("agent_ip"):
        ev.agent_ip = str(item["agent_ip"])
    if item.get("host") or item.get("host_name"):
        ev.host_name = str(item.get("host") or item.get("host_name"))
    if item.get("body"):
        ev.body = str(item["body"])
    if item.get("ts"):
        try:
            ev.ts = float(item["ts"])
        except (TypeError, ValueError):
            pass

    if item.get("src_ip"):
        ip = parse_ip(item["src_ip"])
        if ip is not None:
            ev.remote_ip = str(ip)
            ev.remote_ips = [str(ip)]
    elif isinstance(item.get("ips"), list) and item["ips"]:
        parsed = [str(parse_ip(x)) for x in item["ips"] if parse_ip(x) is not None]
        if parsed:
            ev.remote_ip, ev.remote_ips = parsed[0], parsed

    ev.severity = SEVERITY_BY_EVENT.get(ev.event_type, item.get("severity") or ev.severity)
    if ev.category == "other" and ev.event_type in NETWORK_EVENTS:
        ev.category = "network_inbound"
        ev.direction = "inbound"
    return ev

"""IP 归一化与地址属性判定。

设计原则：本模块只做"这个地址在语法/语义上是什么"，不做任何封禁决策。
所有"要不要封"的判断都在 policy.py。
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# ---------------------------------------------------------------- L0 硬保留段
# 这些网段永远不允许进入封禁流程（内网、回环、组播、文档段、CGNAT 等）。
# 顺序有意义：先匹配到的 label 生效。
BUILTIN_RESERVED: list[tuple[str, str]] = [
    ("0.0.0.0/8", "本网络（0/8）"),
    ("10.0.0.0/8", "私网 A 类"),
    ("100.64.0.0/10", "运营商级 NAT（CGNAT）"),
    ("127.0.0.0/8", "回环"),
    ("169.254.0.0/16", "链路本地"),
    ("172.16.0.0/12", "私网 B 类"),
    ("192.0.0.0/24", "IETF 协议分配"),
    ("192.0.2.0/24", "文档示例段"),
    ("192.168.0.0/16", "私网 C 类"),
    ("198.18.0.0/15", "基准测试段"),
    ("198.51.100.0/24", "文档示例段"),
    ("203.0.113.0/24", "文档示例段"),
    ("224.0.0.0/4", "组播"),
    ("240.0.0.0/4", "保留"),
    ("255.255.255.255/32", "广播"),
    ("::1/128", "IPv6 回环"),
    ("fc00::/7", "IPv6 唯一本地"),
    ("fe80::/10", "IPv6 链路本地"),
    ("2001:db8::/32", "IPv6 文档段"),
    ("ff00::/8", "IPv6 组播"),
]
_BUILTIN_NETS: list[tuple[IPNetwork, str]] = [
    (ipaddress.ip_network(n), label) for n, label in BUILTIN_RESERVED
]

# 有些地址是"公网但绝不能封"的，单独标记，便于报表区分
SPECIAL_PUBLIC_HINTS: list[tuple[str, str]] = [
    ("192.88.99.0/24", "6to4 中继"),
]

_PORT_SUFFIX = re.compile(r"^(?P<ip>.+?)(?::(?P<port>\d{1,5}))?$")
_IPV4_IN_TEXT = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)


def parse_ip(value: object) -> Optional[IPAddress]:
    """把各种写法归一成 ip_address 对象；失败返回 None。

    支持：1.2.3.4 / 1.2.3.4:443 / [2001:db8::1]:443 / " 1.2.3.4 " / 带引号
    """
    if value is None:
        return None
    s = str(value).strip().strip("\"'").strip()
    if not s:
        return None

    # [v6]:port
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]

    try:
        return ipaddress.ip_address(s)
    except ValueError:
        pass

    # v4:port
    if s.count(":") == 1 and "." in s:
        host = s.rsplit(":", 1)[0]
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None
    return None


def builtin_reason(ip: IPAddress) -> Optional[str]:
    """命中 L0 硬保留段则返回原因，否则 None。"""
    for net, label in _BUILTIN_NETS:
        if ip.version == net.version and ip in net:
            return label
    return None


def is_public(ip: IPAddress) -> bool:
    """是否公网可路由地址（且不属于 L0 保留段）。"""
    if builtin_reason(ip) is not None:
        return False
    return ip.is_global


def classify(ip: IPAddress) -> str:
    """给地址打一个粗分类，用于报表与策略分支。"""
    reason = builtin_reason(ip)
    if reason:
        return f"reserved:{reason}"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link_local"
    return "public"


def extract_ipv4_candidates(text: str) -> list[str]:
    """从自由文本里抓所有 IPv4 字面量（去重、保序）。"""
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _IPV4_IN_TEXT.finditer(text):
        s = m.group(0)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def collapse_to_cidrs(ips: list[str]) -> list[str]:
    """把 IP 列表压缩成最小 CIDR 集合（用于 EDL，减小体积）。

    无法解析的条目原样保留，避免静默丢数据。
    """
    nets: list[IPNetwork] = []
    leftover: list[str] = []
    for raw in ips:
        ip = parse_ip(raw)
        if ip is None:
            leftover.append(str(raw))
            continue
        nets.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))

    by_version: dict[int, list[IPNetwork]] = {}
    for n in nets:
        by_version.setdefault(n.version, []).append(n)

    collapsed: list[str] = []
    for version in sorted(by_version):
        collapsed.extend(str(n) for n in ipaddress.collapse_addresses(by_version[version]))
    return sorted(collapsed) + sorted(leftover)

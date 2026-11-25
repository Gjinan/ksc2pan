"""解析层回归测试：这些断言就是"格式漂移"的报警器。

样本全部来自 tools/samples/ksc_events.log，新增现场样本时请同步加断言。
"""
from pathlib import Path

from ksc2pan.ksc_parser import parse_line, parse_payload

SAMPLES = Path(__file__).resolve().parents[1] / "tools" / "samples" / "ksc_events.log"
LINES = [ln for ln in SAMPLES.read_text(encoding="utf-8").splitlines() if ln.strip()]


def test_attack_event_basic_fields():
    ev = parse_line(LINES[0])
    assert ev.event_type == "GNRL_EV_ATTACK_DETECTED"
    assert ev.agent_ip == "10.10.10.10"
    assert ev.host_name == "PC-001"
    assert ev.remote_ip == "45.83.12.77"
    assert ev.category == "network_inbound"
    assert ev.direction == "inbound"
    assert ev.severity == "critical"


def test_remote_label_english():
    ev = parse_line(
        "<134>1 2026-11-25T08:00:00Z PC-X KES|12.0.0.0 - GNRL_EV_ATTACK_DETECTED "
        '[event@11111 et="GNRL_EV_ATTACK_DETECTED" hdn="PC-X" hip="10.1.2.3"] '
        "Blocked\\r\\nRemote IP address: 8.8.4.4\\r\\nProtocol: TCP"
    )
    assert ev.remote_ip == "8.8.4.4"


def test_remote_label_chinese_with_space():
    ev = parse_line(
        "<134>1 2026-11-25T08:00:00Z PC-Y KES|12.0.0.0 - 000007d1 "
        '[event@11111 et="000007d1" hdn="PC-Y" hip="10.1.2.4"] '
        "已阻止\\r\\n远程 IP 地址: 1.2.3.4\\r\\n端口: 80"
    )
    assert ev.remote_ip == "1.2.3.4"
    assert ev.category == "network_inbound"
    assert ev.severity == "high"


def test_web_event_captures_url():
    ev = parse_line(
        "<134>1 2026-11-25T08:00:00Z PC-Z KES|12.0.0.0 - GNRL_EV_WEB_URL_BLOCKED "
        '[event@11111 et="GNRL_EV_WEB_URL_BLOCKED" p2="http://bad.example.com/x.exe" hdn="PC-Z" hip="10.1.2.5"] '
        "对象: http://bad.example.com/x.exe"
    )
    assert ev.category == "web"
    assert ev.direction == "outbound"
    assert any("bad.example.com" in u for u in ev.urls)


def test_file_event_has_no_remote_ip():
    ev = parse_line(
        "<134>1 2026-11-25T08:00:00Z PC-F KES|12.0.0.0 - GNRL_EV_VIRUS_FOUND "
        '[event@11111 et="GNRL_EV_VIRUS_FOUND" hdn="PC-F" hip="10.1.2.6"] 对象: C:\\tmp\\a.exe'
    )
    assert ev.category == "file"
    assert ev.remote_ip is None


def test_garbage_line_never_raises():
    ev = parse_line(LINES[-1])
    assert ev.event_type == ""
    assert ev.category == "other"


def test_agent_ip_not_taken_as_attacker():
    """正文里只有终端自身 IP 时，不能把终端当成攻击源。"""
    ev = parse_line(
        "<134>1 2026-11-25T08:00:00Z PC-A KES|12.0.0.0 - 000007d1 "
        '[event@11111 et="000007d1" hdn="PC-A" hip="10.9.9.9"] 无对端信息 10.9.9.9'
    )
    assert ev.remote_ip is None


def test_structured_payload_overrides():
    ev = parse_payload({"raw": LINES[0], "src_ip": "9.9.9.9", "host": "H-1"})
    assert ev.remote_ip == "9.9.9.9"
    assert ev.host_name == "H-1"


def test_parse_payload_without_raw():
    ev = parse_payload(
        {"event_type": "GNRL_EV_ATTACK_DETECTED", "src_ip": "45.1.2.3", "host": "H-2", "source": "vector"}
    )
    assert ev.event_type == "GNRL_EV_ATTACK_DETECTED"
    assert ev.category == "network_inbound"
    assert ev.remote_ip == "45.1.2.3"

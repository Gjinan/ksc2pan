"""服务层端到端测试（mock 执行器，不碰真实 PA）。

覆盖：观察→封禁→续期、白名单跳过、内网转工单、升级待审批、域名通道、撤销、熔断、到期、白名单反查。
"""
import json
import time
from pathlib import Path

import pytest

from ksc2pan.config import Config
from ksc2pan.ksc_parser import KscEvent
from ksc2pan.service import Service

WL = """
version: "test"
assets:
  - cidr: 222.128.16.0/28
    why: 出口 NAT
temporary: []
windows: []
"""


@pytest.fixture()
def svc(tmp_path) -> Service:
    (tmp_path / "wl.yaml").write_text(WL, encoding="utf-8")
    cfg = Config()
    cfg.service.data_dir = str(tmp_path / "data")
    cfg.service.edl_dir = str(tmp_path / "data" / "edl")
    cfg.service.dry_run = True
    cfg.whitelist.path = str(tmp_path / "wl.yaml")
    cfg.paloalto.mode = "mock"
    return Service(cfg)


def mk(ip: str, et: str = "GNRL_EV_ATTACK_DETECTED", host: str = "PC-1",
       severity: str = "critical") -> KscEvent:
    return KscEvent(
        raw="", ts=time.time(), event_type=et, host_name=host, agent_ip="10.10.10.10",
        category="network_inbound", severity=severity, direction="inbound",
        remote_ip=ip, remote_ips=[ip],
    )


def edl_lines(svc: Service, name: str) -> list[str]:
    path = Path(svc.cfg.service.edl_dir) / name
    return path.read_text(encoding="utf-8").split() if path.exists() else []


def test_observe_then_block_then_refresh(svc):
    d1 = svc.process_event(mk("45.83.12.77"))
    assert d1[0]["action"] == "observe"

    d2 = svc.process_event(mk("45.83.12.77", host="PC-2"))
    assert d2[0]["action"] == "dag"
    assert d2[0]["applied"] is True
    assert d2[0]["ttl"] == 14400

    row = svc.store.active_block("45.83.12.77")
    assert row is not None and row["tier"] == "L2" and row["dag_synced"] == 1

    d3 = svc.process_event(mk("45.83.12.77"))
    assert d3[0]["action"] == "refresh"

    log = (Path(svc.cfg.service.data_dir) / "mock_pa_dag.jsonl").read_text(encoding="utf-8")
    assert '"register"' in log


def test_whitelisted_nat_is_skipped(svc):
    d = svc.process_event(mk("222.128.16.5"))
    assert d[0]["action"] == "whitelisted"
    assert d[0]["applied"] is False
    assert svc.store.active_block("222.128.16.5") is None


def test_internal_source_becomes_ticket(svc):
    d = svc.process_event(mk("10.20.30.40"))
    assert d[0]["action"] == "internal"
    assert "隔离" in d[0]["ticket"]
    assert svc.store.active_block("10.20.30.40") is None


def test_escalation_to_pending(svc):
    actions = []
    for host in ("PC-A", "PC-B", "PC-C"):
        actions.append(svc.process_event(mk("103.145.22.19", "000007d1", host, "high"))[0]["action"])
    assert actions[0] == "observe"
    assert actions[1] == "dag"
    assert actions[2] == "pending"
    pending = svc.store.list_blocks(status="pending")
    assert any(b["ip"] == "103.145.22.19" for b in pending)

    res = svc.approve("103.145.22.19", "tester")
    assert res["ok"] is True
    assert svc.store.active_block("103.145.22.19")["edl"] == 1
    assert any(line.startswith("103.145.22.19") for line in edl_lines(svc, "ip-block.txt"))


def test_domain_event_goes_to_sinkhole_list(svc):
    ev = KscEvent(
        raw="", ts=time.time(), event_type="GNRL_EV_WEB_URL_BLOCKED", host_name="PC-W",
        category="web", severity="high", direction="outbound",
        urls=["http://malware.example.com/payload.exe"], remote_ips=[],
    )
    d = svc.process_event(ev)
    assert d[0]["action"] == "domain"
    assert "malware.example.com" in edl_lines(svc, "domain-sink.txt")


def test_revoke(svc):
    svc.process_event(mk("45.83.12.77", host="PC-1"))
    svc.process_event(mk("45.83.12.77", host="PC-2"))
    assert svc.store.active_block("45.83.12.77") is not None

    res = svc.revoke("45.83.12.77", "tester", "误封")
    assert res["ok"] is True
    assert svc.store.get_block("45.83.12.77")["status"] == "revoked"
    assert svc.store.active_block("45.83.12.77") is None


def test_emergency_stop(svc):
    svc.set_estop(True, "tester")
    d = svc.process_event(mk("45.83.12.77"))
    assert d[0]["action"] == "estop"
    svc.set_estop(False, "tester")
    assert svc.process_event(mk("45.83.99.1"))[0]["action"] == "observe"


def test_ttl_expiry(svc):
    svc.process_event(mk("45.83.12.77", host="PC-1"))
    svc.process_event(mk("45.83.12.77", host="PC-2"))
    with svc.store._conn() as conn:  # noqa: SLF001 - 测试里直接改过期时间
        conn.execute("UPDATE blocks SET expires=? WHERE ip=?", (time.time() - 5, "45.83.12.77"))

    out = svc.tick()
    assert out["expired"] == 1
    assert svc.store.get_block("45.83.12.77")["status"] == "expired"
    assert edl_lines(svc, "ip-block.txt") == []


def test_whitelist_reconcile_revokes_existing(svc):
    svc.process_event(mk("45.83.12.77", host="PC-1"))
    svc.process_event(mk("45.83.12.77", host="PC-2"))
    assert svc.store.active_block("45.83.12.77") is not None

    # 事后把该 IP 加进白名单（模拟"同事发现误封，加白"）
    Path(svc.cfg.whitelist.path).write_text(
        'version: "test"\n'
        "assets:\n"
        "  - cidr: 222.128.16.0/28\n"
        "    why: 出口 NAT\n"
        "  - cidr: 45.83.12.77/32\n"
        "    why: 业务方确认\n"
        "temporary: []\n"
        "windows: []\n",
        encoding="utf-8",
    )
    svc.whitelist.load(strict=False)

    out = svc.tick()
    assert out["whitelist_revoked"] >= 1
    assert svc.store.get_block("45.83.12.77")["status"] == "revoked"


def test_dry_run_writes_no_real_push(svc):
    svc.process_event(mk("45.83.12.77", host="PC-1"))
    svc.process_event(mk("45.83.12.77", host="PC-2"))
    log = (Path(svc.cfg.service.data_dir) / "mock_pa_dag.jsonl").read_text(encoding="utf-8")
    rec = json.loads(log.splitlines()[0])
    assert rec["op"] == "register" and rec["ip"] == "45.83.12.77"

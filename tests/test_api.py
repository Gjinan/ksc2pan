"""HTTP 层测试：NDJSON 批量、单条 JSON、白名单查询、熔断。"""
import importlib
import json
from pathlib import Path

from fastapi.testclient import TestClient


def _write_cfg(tmp_path: Path) -> Path:
    d = str(tmp_path).replace("\\", "/")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"""service:
  data_dir: {d}/data
  edl_dir: {d}/data/edl
  dry_run: true
whitelist:
  path: {d}/wl.yaml
paloalto:
  mode: mock
""",
        encoding="utf-8",
    )
    (tmp_path / "wl.yaml").write_text(
        'version: "test"\nassets:\n  - cidr: 222.128.16.0/28\n    why: 出口 NAT\n',
        encoding="utf-8",
    )
    return cfg


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("KSC2PAN_CONFIG", str(cfg))
    monkeypatch.setenv("KSC2PAN_TOKEN", "")
    monkeypatch.setenv("PA_MODE", "mock")
    import ksc2pan.main as main

    importlib.reload(main)
    return TestClient(main.app)


ATTACK = (
    "<134>1 2026-11-25T08:00:01.000Z PC-001 KES|12.0.0.0 - GNRL_EV_ATTACK_DETECTED "
    '[event@11111 et="GNRL_EV_ATTACK_DETECTED" hdn="PC-001" hip="10.10.10.10"] '
    "已阻止\\r\\n远程 IP 地址: 45.83.12.77"
)


def test_ndjson_ingest_and_query(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/health").json()["status"] == "ok"

        body = "\n".join(json.dumps({"raw": ATTACK}) for _ in range(2))
        resp = client.post("/ingest", content=body, headers={"content-type": "application/json"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 2
        assert [d["action"] for d in data["decisions"]] == ["observe", "dag"]

        blocks = client.get("/api/blocks").json()["items"]
        assert any(b["ip"] == "45.83.12.77" and b["tier"] == "L2" for b in blocks)

        check = client.get("/api/whitelist/check", params={"ip": "222.128.16.5"}).json()
        assert check["whitelisted"] is True
        assert check["hit"]["layer"] == "L1"

        internal = client.get("/api/whitelist/check", params={"ip": "10.1.2.3"}).json()
        assert internal["hit"]["layer"] == "L0"

        metrics = client.get("/metrics").text
        assert "ksc2pan_blocks_active 1" in metrics


def test_single_json_and_raw_line(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r1 = client.post("/ingest", json={"raw": ATTACK})
        assert r1.json()["decisions"][0]["action"] == "observe"

        r2 = client.post("/ingest", content=ATTACK, headers={"content-type": "text/plain"})
        assert r2.status_code == 200
        assert r2.json()["decisions"][0]["action"] == "dag"


def test_emergency_stop_endpoint(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.post("/api/estop", params={"on": True}).json()["emergency_stop"] is True
        r = client.post("/ingest", json={"raw": ATTACK}).json()
        assert r["decisions"][0]["action"] == "estop"
        client.post("/api/estop", params={"on": False})


def test_deadletter_accepts_garbage(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        r = client.post("/deadletter", json={"raw": "totally broken line"})
        assert r.status_code == 200
        assert r.json()["stored"] == 1
        assert client.get("/stats").json()["metrics"]["parse_errors"] == 1

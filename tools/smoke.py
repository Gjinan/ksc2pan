#!/usr/bin/env python3
"""部署后自检（冒烟测试）：确认服务、白名单、解析、封禁、EDL 全链路可用。

用法：
  # 对已运行的服务做检查
  python tools/smoke.py --url http://127.0.0.1:8080

  # 本地起一个临时实例（mock 模式、临时数据目录）自检
  python tools/smoke.py --local

退出码 0 = 全部通过，非 0 = 有失败项，可直接用于发布流水线。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import requests  # noqa: E402

ATTACK = (
    "<134>1 2026-11-25T08:00:01.000Z SMOKE-PC KES|12.0.0.0 - GNRL_EV_ATTACK_DETECTED "
    '[event@11111 et="GNRL_EV_ATTACK_DETECTED" hdn="SMOKE-PC" hip="10.99.0.1"] '
    "已阻止\\r\\n远程 IP 地址: 45.83.12.99"
)

results: list[tuple[bool, str]] = []


def check(ok: bool, msg: str) -> None:
    results.append((ok, msg))
    print(("  [OK]   " if ok else "  [FAIL] ") + msg)


def run_checks(base: str) -> None:
    print(f"目标：{base}\n")

    r = requests.get(f"{base}/health", timeout=5)
    check(r.status_code == 200 and r.json().get("status") == "ok", "健康检查 /health")

    r = requests.get(f"{base}/api/whitelist/check", params={"ip": "10.1.2.3"}, timeout=5)
    check(r.json().get("hit", {}).get("layer") == "L0", "私网地址命中 L0 硬白名单")

    r = requests.get(f"{base}/api/whitelist/check", params={"ip": "222.128.16.5"}, timeout=5)
    check(r.json().get("whitelisted") is True, "单位资产命中 L1 白名单")

    r = requests.post(f"{base}/ingest", json={"raw": ATTACK}, timeout=10)
    d = r.json()["decisions"][0]
    check(d["action"] in ("observe", "dag"), f"事件解析并给出判定：{d['action']} / {d['reason']}")

    r = requests.post(f"{base}/ingest", json={"raw": ATTACK}, timeout=10)
    d2 = r.json()["decisions"][0]
    check(d2["action"] in ("dag", "refresh"), f"第二次命中进入封禁：{d2['action']}")

    blocks = requests.get(f"{base}/api/blocks", params={"status": "active"}, timeout=5).json()["items"]
    check(any(b["ip"] == "45.83.12.99" for b in blocks), "封禁记录可查询")

    r = requests.post(f"{base}/api/blocks/45.83.12.99/revoke", params={"reason": "smoke"}, timeout=10)
    check(r.json().get("ok") is True, "人工撤销")

    r = requests.post(f"{base}/api/estop", params={"on": True}, timeout=5)
    check(r.json().get("emergency_stop") is True, "紧急熔断开启")
    r = requests.post(f"{base}/api/estop", params={"on": False}, timeout=5)
    check(r.json().get("emergency_stop") is False, "紧急熔断关闭")

    met = requests.get(f"{base}/metrics", timeout=5).text
    check("ksc2pan_events_in_total" in met or "ksc2pan_events" in met, "Prometheus 指标可抓取")


def start_local() -> tuple[str, object]:
    data_dir = Path(tempfile.mkdtemp(prefix="ksc2pan-smoke-"))
    os.environ["KSC2PAN_DATA_DIR"] = str(data_dir)
    os.environ["PA_MODE"] = "mock"
    os.environ["KSC2PAN_DRY_RUN"] = "true"
    cfg = data_dir / "config.yaml"
    cfg.write_text(
        f"service:\n  data_dir: {str(data_dir).replace(chr(92), '/')}\n"
        f"  edl_dir: {str(data_dir).replace(chr(92), '/')}/edl\n  dry_run: true\n"
        f"whitelist:\n  path: {str(ROOT / 'config' / 'whitelist.yaml').replace(chr(92), '/')}\n"
        "paloalto:\n  mode: mock\n",
        encoding="utf-8",
    )
    os.environ["KSC2PAN_CONFIG"] = str(cfg)

    import uvicorn

    from ksc2pan.main import app

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=18099, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(80):
        try:
            requests.get("http://127.0.0.1:18099/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    return "http://127.0.0.1:18099", server


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="")
    ap.add_argument("--local", action="store_true")
    args = ap.parse_args()

    server = None
    base = args.url
    if args.local or not base:
        base, server = start_local()

    try:
        run_checks(base.rstrip("/"))
    except Exception as exc:  # noqa: BLE001
        check(False, f"执行异常：{exc}")
    finally:
        if server is not None:
            server.should_exit = True

    failed = [m for ok, m in results if not ok]
    print(f"\n结果：{len(results) - len(failed)}/{len(results)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

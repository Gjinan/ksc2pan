#!/usr/bin/env python3
"""离线回放工具：把 KSC syslog 样本喂给同一套决策逻辑，打印每一步判定。

用途：
  1. 没有 PA / 没有真实 KSC 时先验证解析与策略；
  2. 上线前用真实样本做回归；
  3. 给同事演示"这条事件为什么会封 / 为什么不封"。

用法：
  python tools/replay.py --file tools/samples/ksc_events.log
  python tools/replay.py --file samples.log --config config/config.yaml --reset
  python tools/replay.py --file samples.log --http http://127.0.0.1:8080/ingest
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import requests  # noqa: E402

from ksc2pan.config import load_config  # noqa: E402
from ksc2pan.service import Service  # noqa: E402

ACTION_LABEL = {
    "observe": "观察",
    "dag": "临时封禁(L2)",
    "edl": "长期封禁(L3)",
    "pending": "待审批(L3)",
    "whitelisted": "白名单跳过",
    "internal": "内网源跳过",
    "ignore": "不适用",
    "refresh": "已封禁/续期",
    "estop": "熔断跳过",
    "domain": "域名清单",
    "error": "处理异常",
}


def read_events(path: Path) -> list[str]:
    lines = [ln.rstrip("\n") for ln in path.read_text(encoding="utf-8").splitlines()]
    return [ln for ln in lines if ln.strip() and not ln.startswith("#")]


def print_table(rows: list[dict]) -> None:
    head = f"{'#':>3}  {'事件类型':<28} {'终端':<10} {'对端 IP':<16} {'判定':<12} 说明"
    print(head)
    print("-" * len(head))
    for i, r in enumerate(rows, 1):
        action = r.get("action", "")
        print(
            f"{i:>3}  {(r.get('event_type') or '-'):<28} {(r.get('host') or '-'):<10} "
            f"{(r.get('ip') or '-'):<16} {ACTION_LABEL.get(action, action):<12} {r.get('reason','')}"
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="原始 syslog 样本文件，一行一条")
    ap.add_argument("--config", default=str(ROOT / "config" / "config.yaml"))
    ap.add_argument("--data-dir", default="", help="数据目录，默认临时目录")
    ap.add_argument("--http", default="", help="改为通过 HTTP 灌给运行中的服务")
    ap.add_argument("--reset", action="store_true", help="清空数据目录后重跑")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出全部判定")
    args = ap.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else Path(tempfile.mkdtemp(prefix="ksc2pan-replay-"))
    if args.reset:
        shutil.rmtree(data_dir, ignore_errors=True)
    os.environ["KSC2PAN_DATA_DIR"] = str(data_dir)
    os.environ.setdefault("PA_MODE", "mock")
    os.environ.setdefault("KSC2PAN_DRY_RUN", "true")

    events = read_events(Path(args.file))
    print(f"样本 {len(events)} 条，数据目录 {data_dir}\n")

    rows: list[dict] = []
    if args.http:
        resp = requests.post(args.http, json=[{"raw": e} for e in events], timeout=30)
        resp.raise_for_status()
        rows = resp.json().get("decisions", [])
        print_table(rows)
        return 0

    cfg = load_config(args.config)
    cfg.service.dry_run = True
    cfg.paloalto.mode = "mock"
    cfg.whitelist.path = str(ROOT / "config" / "whitelist.yaml")
    service = Service(cfg)

    for raw in events:
        rows.extend(service.process_payload([{"raw": raw}]))

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print_table(rows)

    service.refresh_edl()
    stats = service.stats()
    print("\n=== 汇总 ===")
    print(f"活跃封禁 {stats['store']['blocks_active']} 条 / 待审批 "
          f"{len(service.store.list_blocks(status='pending'))} 条 / EDL {stats['store']['blocks_edl']} 条")
    print(f"白名单：{stats['whitelist']['assets']} 条资产、{stats['whitelist']['temporary']} 条临时例外")
    for key in ("ip_block", "watch", "domain", "whitelist"):
        path = Path(cfg.service.edl_dir) / service.edl.FILES[key]
        content = path.read_text(encoding="utf-8").strip().splitlines() if path.exists() else []
        print(f"{path.name:<16} {len(content):>3} 条：{content[:6]}{' …' if len(content) > 6 else ''}")
    print(f"\nPA 动作流水（mock）：{Path(cfg.service.data_dir) / 'mock_pa_dag.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

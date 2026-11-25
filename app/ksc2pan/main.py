"""KSC2PAN HTTP 入口。

只做协议适配与鉴权，业务全在 service.py —— 这样 tools/replay.py 可以不经过 HTTP 直接跑。
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from . import __version__
from .service import Service

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("ksc2pan.api")

SERVICE = Service.from_config(os.environ.get("KSC2PAN_CONFIG"))
API_TOKEN = os.environ.get("KSC2PAN_TOKEN", "")


def require_token(x_api_token: str | None = Header(default=None)) -> None:
    if API_TOKEN and x_api_token != API_TOKEN:
        raise HTTPException(status_code=401, detail="invalid api token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    SERVICE.start()
    log.info("ksc2pan %s 启动，dry_run=%s", __version__, SERVICE.cfg.service.dry_run)
    yield
    SERVICE.stop()


app = FastAPI(title="KSC2PAN", version=__version__, lifespan=lifespan)


def _items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    if isinstance(payload, dict):
        events = payload.get("events")
        if isinstance(events, list):
            return [p for p in events if isinstance(p, dict)]
        return [payload]
    raise HTTPException(status_code=400, detail="payload 必须是对象、数组或 {events:[...]}")


def _parse_body(raw: bytes) -> list[dict[str, Any]]:
    """兼容三种请求体：单个 JSON、JSON 数组、NDJSON（Vector 批量默认格式），
    以及直接贴原始 syslog 行。"""
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise HTTPException(status_code=400, detail="请求体为空")

    if text[0] in "[{":
        try:
            return _items(json.loads(text))
        except json.JSONDecodeError:
            pass

    items: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                items.append(json.loads(line))
                continue
            except json.JSONDecodeError:
                pass
        items.append({"raw": line})
    if not items:
        raise HTTPException(status_code=400, detail="无法解析请求体")
    return items


@app.get("/health")
def health() -> dict[str, Any]:
    stats = SERVICE.stats()
    return {
        "status": "ok",
        "version": __version__,
        "dry_run": stats["mode"]["dry_run"],
        "emergency_stop": stats["mode"]["emergency_stop"],
        "pa": stats["mode"]["pa"],
        "whitelist_error": SERVICE.whitelist.last_error,
    }


@app.post("/ingest")
async def ingest(request: Request) -> dict[str, Any]:
    items = _parse_body(await request.body())
    decisions = SERVICE.process_payload(items)
    return {"accepted": len(items), "decisions": decisions}


@app.post("/deadletter")
async def deadletter(request: Request) -> dict[str, Any]:
    """Vector 解析失败的报文进这里，进库+计数，绝不静默丢弃。"""
    items = _parse_body(await request.body())
    for item in items:
        raw = str(item.get("raw") or item.get("message") or "")
        SERVICE.metrics["parse_errors"] += 1
        SERVICE.store.audit("vector", "parse_error", "", {"raw": raw[:2000]})
    return {"stored": len(items)}


@app.get("/stats")
def stats() -> dict[str, Any]:
    return SERVICE.stats()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    st = SERVICE.stats()
    lines = ["# KSC2PAN metrics"]
    for key, value in st["metrics"].items():
        lines.append(f"ksc2pan_{key}_total {value}")
    for key in ("events_24h", "blocks_active", "blocks_edl"):
        lines.append(f"ksc2pan_{key} {st['store'][key]}")
    lines.append(f"ksc2pan_whitelist_assets {st['whitelist']['assets']}")
    return "\n".join(lines) + "\n"


@app.get("/api/blocks")
def list_blocks(status: str = Query("active"), limit: int = Query(200, ge=1, le=2000)) -> dict[str, Any]:
    return {"status": status, "items": SERVICE.store.list_blocks(status=status, limit=limit)}


@app.post("/api/blocks/{ip}/revoke", dependencies=[Depends(require_token)])
def revoke(ip: str, reason: str = Query("manual"), actor: str = Query("api")) -> dict[str, Any]:
    return SERVICE.revoke(ip, actor, reason)


@app.post("/api/blocks/{ip}/approve", dependencies=[Depends(require_token)])
def approve(ip: str, actor: str = Query("api")) -> dict[str, Any]:
    return SERVICE.approve(ip, actor)


@app.get("/api/whitelist")
def whitelist_stats() -> dict[str, Any]:
    return SERVICE.whitelist.stats()


@app.get("/api/whitelist/check")
def whitelist_check(ip: str = Query(..., description="要检查的 IP")) -> dict[str, Any]:
    return SERVICE.whitelist.check(ip)


@app.post("/api/whitelist/reload", dependencies=[Depends(require_token)])
def whitelist_reload(actor: str = Query("api")) -> dict[str, Any]:
    return SERVICE.reload_whitelist(actor)


@app.post("/api/estop", dependencies=[Depends(require_token)])
def estop(on: bool = Query(True), actor: str = Query("api")) -> dict[str, Any]:
    return SERVICE.set_estop(on, actor)


@app.post("/api/tick", dependencies=[Depends(require_token)])
def tick() -> dict[str, Any]:
    return SERVICE.tick()


@app.get("/api/audit")
def audit(limit: int = Query(100, ge=1, le=1000)) -> dict[str, Any]:
    return {"items": SERVICE.store.list_audit(limit=limit)}

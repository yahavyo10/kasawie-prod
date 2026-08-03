import os
import json
import pathlib
from typing import Optional

from dotenv import load_dotenv
load_dotenv()  # picks up backend/.env if present

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from pipeline import run_phase1, run_phase2, run_phase3_attacker_history
from cve_db import parse_cve_database
import inventory_db

# Bump this string any time you get a fresh copy of this project, and check it
# in the UI status pill / GET /api/health -- it's the fastest way to confirm
# you're actually running the code you think you're running, not a stale copy.
BUILD_VERSION = "sherlog-v20-2026-08-03-inventory-rebuilt"

BASE_DIR = pathlib.Path(__file__).parent
SAMPLE_DIR = BASE_DIR / "sample_data"
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = FastAPI(title="Sherlog")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"

# Standard headers that discourage intermediate proxies from buffering the
# stream (e.g. some reverse proxies buffer text/event-stream responses,
# which would turn the live step-by-step feed into one big delayed dump).
# Harmless to set even on setups that don't need them.
SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


async def _read_json_upload(f: Optional[UploadFile]):
    if f is None:
        return None
    raw = await f.read()
    data = json.loads(raw)
    if isinstance(data, dict) and "logs" in data:
        return data["logs"]
    return data


def _load_sample(name: str):
    with open(SAMPLE_DIR / name) as f:
        data = json.load(f)
    return data.get("logs", data) if isinstance(data, dict) else data


def _run_pipeline(wt, wt1, wt2, cve_defs=None):
    """Shared driver for both /api/investigate and /api/investigate/demo.
    Runs phase 1, captures its return value via StopIteration.value (the
    generator's return, not a yielded event), then runs phase 2 if both
    prior windows are available. cve_defs is optional and, if given, gets
    cross-referenced against the device timeline in phase 2 (see cve_db.py).
    The network inventory DB config (see inventory_db.py) is always pulled
    from environment variables server-side -- there's no request field or UI
    for it. If INVENTORY_DB_URL isn't set, default_config() returns None and
    the exposure_scan step is skipped entirely, same as the CVE database."""
    db_config = inventory_db.default_config()
    result_holder = {}

    def phase1_events():
        gen = run_phase1(wt)
        try:
            while True:
                ev = next(gen)
                yield _sse(ev)
        except StopIteration as stop:
            result_holder["root_cause"] = stop.value

    for chunk in phase1_events():
        yield chunk

    root_cause = result_holder.get("root_cause")
    if root_cause is None:
        yield _sse({"step": "pipeline", "status": "error", "data": {"message": "Phase 1 failed, stopping."}})
        return

    if wt1 is None or wt2 is None:
        yield _sse({
            "step": "pipeline", "status": "awaiting_phase2",
            "data": {"message": "Root cause found. Upload the 2 prior windows to run phase 2."}
        })
        return

    def phase2_events():
        gen = run_phase2(root_cause, wt, wt1, wt2, cve_defs=cve_defs, db_config=db_config)
        try:
            while True:
                ev = next(gen)
                yield _sse(ev)
        except StopIteration:
            pass

    for chunk in phase2_events():
        yield chunk

    yield _sse({"step": "pipeline", "status": "complete", "data": None})


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "version": BUILD_VERSION,
        "groq_key_configured": bool(os.environ.get("JUBAL_API_KEY")),
        "inventory_configured": inventory_db.is_configured(),
    }


@app.post("/api/investigate")
async def investigate(
    window_t: UploadFile = File(...),
    window_t1: Optional[UploadFile] = File(None),
    window_t2: Optional[UploadFile] = File(None),
    cve_database: Optional[UploadFile] = File(None),
):
    wt = await _read_json_upload(window_t)
    wt1 = await _read_json_upload(window_t1)
    wt2 = await _read_json_upload(window_t2)
    cve_defs = None
    if cve_database is not None:
        raw = json.loads(await cve_database.read())
        cve_defs = parse_cve_database(raw)
    return StreamingResponse(_run_pipeline(wt, wt1, wt2, cve_defs=cve_defs), media_type="text/event-stream", headers=SSE_HEADERS)


@app.post("/api/investigate/demo")
async def investigate_demo(cve_database: Optional[UploadFile] = File(None)):
    wt = _load_sample("window_t.json")
    wt1 = _load_sample("window_t1.json")
    wt2 = _load_sample("window_t2.json")
    cve_defs = None
    if cve_database is not None:
        raw = json.loads(await cve_database.read())
        cve_defs = parse_cve_database(raw)
    return StreamingResponse(_run_pipeline(wt, wt1, wt2, cve_defs=cve_defs), media_type="text/event-stream", headers=SSE_HEADERS)


@app.post("/api/attacker-history")
async def attacker_history(
    history_log: UploadFile = File(...),
    cve_database: Optional[UploadFile] = File(None),
):
    """Phase 3: reconstructs one attacker IP's footprint from a log file the
    user has already filtered down to that IP (e.g. via an Elastic query
    scoped to source/client IP), spanning up to a year."""
    logs = await _read_json_upload(history_log)
    cve_defs = None
    if cve_database is not None:
        raw = json.loads(await cve_database.read())
        cve_defs = parse_cve_database(raw)

    def run():
        gen = run_phase3_attacker_history(logs, cve_defs=cve_defs)
        try:
            while True:
                ev = next(gen)
                yield _sse(ev)
        except StopIteration:
            pass
        yield _sse({"step": "pipeline", "status": "complete", "data": None})

    return StreamingResponse(run(), media_type="text/event-stream", headers=SSE_HEADERS)


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

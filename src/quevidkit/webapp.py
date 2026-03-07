from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
import uuid
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from .models import AnalysisOptions
from .pipeline import analyze_video


ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(ROOT / "templates"))
UPLOAD_DIR = Path(os.environ.get("QVK_UPLOAD_DIR", "/tmp/quevidkit_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = int(os.environ.get("QVK_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))
UPLOAD_RETENTION_SECONDS = int(os.environ.get("QVK_UPLOAD_RETENTION_SECONDS", str(24 * 60 * 60)))
KEEP_UPLOADS = os.environ.get("QVK_KEEP_UPLOADS", "0") == "1"


@dataclass
class JobRecord:
    job_id: str
    file_path: str
    options: dict[str, Any]
    status: str = "queued"
    phase: str = "queued"
    progress_percent: int = 0
    message: str = "Queued"
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def touch(self, *, status: str | None = None, phase: str | None = None, progress: int | None = None, message: str | None = None) -> None:
        if status is not None:
            self.status = status
        if phase is not None:
            self.phase = phase
        if progress is not None:
            self.progress_percent = max(0, min(100, int(progress)))
        if message is not None:
            self.message = message
        self.updated_at = datetime.now(timezone.utc).isoformat()


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()

    def put(self, job: JobRecord) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def delete(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.pop(job_id, None)

    def to_status_dict(self, job: JobRecord) -> dict[str, Any]:
        return {
            "job_id": job.job_id,
            "status": job.status,
            "phase": job.phase,
            "progress_percent": job.progress_percent,
            "message": job.message,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
        }


app = FastAPI(title="quevidkit web")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
store = JobStore()
executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="qvk-worker")


def _allowed_filename(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith((".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v"))


def _parse_options(raw_options: str | None) -> AnalysisOptions:
    if not raw_options:
        return AnalysisOptions()
    try:
        data = json.loads(raw_options)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid options JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Options payload must be a JSON object")
    try:
        return AnalysisOptions.from_dict(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _cleanup_old_uploads() -> None:
    now = time.time()
    for file_path in UPLOAD_DIR.glob("*"):
        if not file_path.is_file():
            continue
        try:
            age_s = now - file_path.stat().st_mtime
            if age_s > UPLOAD_RETENTION_SECONDS:
                file_path.unlink(missing_ok=True)
        except OSError:
            continue


async def _save_upload_stream(file: UploadFile, destination: Path) -> int:
    total_bytes = 0
    with destination.open("wb") as handle:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                handle.close()
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Uploaded file exceeds configured size limit")
            handle.write(chunk)
    await file.close()
    if total_bytes < 16:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Uploaded file is too small")
    return total_bytes


def _run_analysis_job(job_id: str) -> None:
    job = store.get(job_id)
    if not job:
        return
    try:
        job.touch(status="processing", phase="extracting_metadata", progress=15, message="Running metadata checks")
        options = AnalysisOptions.from_dict(job.options)
        job.touch(status="processing", phase="forensic_analysis", progress=55, message="Analyzing temporal and quality signals")
        result = analyze_video(job.file_path, options=options)
        job.result = result.to_dict()
        job.touch(status="completed", phase="done", progress=100, message="Analysis complete")
    except Exception as exc:  # pragma: no cover - broad for API resilience
        job.error = str(exc)
        job.touch(status="failed", phase="failed", progress=100, message="Analysis failed")
    finally:
        if not KEEP_UPLOADS:
            try:
                os.remove(job.file_path)
            except OSError:
                pass


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return TEMPLATES.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/jobs")
async def create_job(
    file: UploadFile = File(...),
    options: str | None = Form(default=None),
) -> JSONResponse:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")
    if not _allowed_filename(file.filename):
        raise HTTPException(status_code=415, detail="Unsupported file type")

    parsed_options = _parse_options(options)
    _cleanup_old_uploads()
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    destination = UPLOAD_DIR / f"{job_id}_{Path(file.filename).name}"

    _ = await _save_upload_stream(file, destination)

    job = JobRecord(job_id=job_id, file_path=str(destination), options=parsed_options.__dict__)
    store.put(job)
    executor.submit(_run_analysis_job, job_id)
    return JSONResponse(status_code=202, content=store.to_status_dict(job))


@app.get("/api/v1/jobs/{job_id}")
async def job_status(job_id: str) -> dict[str, Any]:
    job = store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return store.to_status_dict(job)


@app.get("/api/v1/jobs/{job_id}/result")
async def job_result(job_id: str) -> dict[str, Any]:
    job = store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "failed":
        raise HTTPException(status_code=500, detail=job.error or "Analysis failed")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail="Job not completed yet")
    return {"job_id": job_id, "status": "completed", "result": job.result}


@app.delete("/api/v1/jobs/{job_id}")
async def delete_job(job_id: str) -> dict[str, str]:
    job = store.delete(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        os.remove(job.file_path)
    except OSError:
        pass
    return {"status": "deleted", "job_id": job_id}


def run() -> None:
    import uvicorn

    uvicorn.run("quevidkit.webapp:app", host="0.0.0.0", port=8000, reload=False)

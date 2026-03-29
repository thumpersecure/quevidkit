from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
import uuid
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
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

SESSION_KEY_TTL_SECONDS = int(os.environ.get("QVK_SESSION_KEY_TTL_SECONDS", "3600"))
SESSION_KEY_GEN_LIMIT = int(os.environ.get("QVK_SESSION_KEY_GEN_LIMIT", "10"))
SESSION_KEY_GEN_WINDOW_SECONDS = int(os.environ.get("QVK_SESSION_KEY_GEN_WINDOW_SECONDS", "3600"))
SESSION_KEY_JOB_LIMIT = int(os.environ.get("QVK_SESSION_KEY_JOB_LIMIT", "10"))
_session_secret = os.environ.get("QVK_SESSION_KEY_SECRET")
if not _session_secret:
    # Ephemeral fallback keeps secrets out of repo and rotates on each server restart.
    _session_secret = secrets.token_urlsafe(48)


def _iso_from_ts(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


@dataclass
class SessionPrincipal:
    client_id: str
    key_id: str
    remaining_job_creates: int


@dataclass
class SessionKeyRecord:
    key_id: str
    token_hash: str
    client_id: str
    issued_at_s: float
    expires_at_s: float
    remaining_job_creates: int


class SessionKeyManager:
    def __init__(
        self,
        secret: str,
        generation_limit: int,
        generation_window_seconds: int,
        key_ttl_seconds: int,
        key_job_limit: int,
    ) -> None:
        self._secret = secret.encode("utf-8")
        self._generation_limit = generation_limit
        self._generation_window_s = generation_window_seconds
        self._key_ttl_s = key_ttl_seconds
        self._key_job_limit = key_job_limit
        self._keys: dict[str, SessionKeyRecord] = {}
        self._generation_events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _hash_token(self, key_id: str, token_secret: str) -> str:
        payload = f"{key_id}.{token_secret}".encode("utf-8")
        return hmac.new(self._secret, payload, digestmod=hashlib.sha256).hexdigest()

    def _cleanup_locked(self, now_s: float) -> None:
        expired_key_ids = [key_id for key_id, record in self._keys.items() if record.expires_at_s <= now_s]
        for key_id in expired_key_ids:
            self._keys.pop(key_id, None)
        for client_id in list(self._generation_events.keys()):
            events = self._generation_events[client_id]
            while events and (now_s - events[0] > self._generation_window_s):
                events.popleft()
            if not events:
                self._generation_events.pop(client_id, None)

    def issue_key(self, client_id: str, now_s: float | None = None) -> dict[str, Any]:
        current = now_s if now_s is not None else time.time()
        with self._lock:
            self._cleanup_locked(current)
            events = self._generation_events.setdefault(client_id, deque())
            while events and (current - events[0] > self._generation_window_s):
                events.popleft()
            if len(events) >= self._generation_limit:
                reset_after_s = max(1, int(self._generation_window_s - (current - events[0])))
                raise HTTPException(
                    status_code=429,
                    detail="Session key generation rate limit exceeded. Please wait and try again.",
                    headers={"Retry-After": str(reset_after_s)},
                )
            events.append(current)

            key_id = secrets.token_urlsafe(8).replace("-", "").replace("_", "")
            token_secret = secrets.token_urlsafe(24)
            token = f"qvk_{key_id}.{token_secret}"
            record = SessionKeyRecord(
                key_id=key_id,
                token_hash=self._hash_token(key_id, token_secret),
                client_id=client_id,
                issued_at_s=current,
                expires_at_s=current + self._key_ttl_s,
                remaining_job_creates=self._key_job_limit,
            )
            self._keys[key_id] = record
            remaining_generation = max(0, self._generation_limit - len(events))
            return {
                "session_key": token,
                "key_id": key_id,
                "expires_at_utc": _iso_from_ts(record.expires_at_s),
                "expires_in_seconds": self._key_ttl_s,
                "rate_limit": {
                    "limit": self._generation_limit,
                    "remaining": remaining_generation,
                    "window_seconds": self._generation_window_s,
                },
                "job_quota": {
                    "limit": self._key_job_limit,
                    "remaining": record.remaining_job_creates,
                },
            }

    def generation_quota(self, client_id: str, now_s: float | None = None) -> dict[str, Any]:
        current = now_s if now_s is not None else time.time()
        with self._lock:
            self._cleanup_locked(current)
            events = self._generation_events.get(client_id, deque())
            while events and (current - events[0] > self._generation_window_s):
                events.popleft()
            remaining = max(0, self._generation_limit - len(events))
            return {
                "limit": self._generation_limit,
                "remaining": remaining,
                "window_seconds": self._generation_window_s,
            }

    def validate_key(
        self,
        key_text: str,
        client_id: str,
        *,
        consume_job_create: bool = False,
        now_s: float | None = None,
    ) -> SessionPrincipal:
        current = now_s if now_s is not None else time.time()
        if not key_text.startswith("qvk_") or "." not in key_text:
            raise HTTPException(status_code=401, detail="Invalid session key format.")
        raw_key_id, raw_secret = key_text[4:].split(".", maxsplit=1)
        if not raw_key_id or not raw_secret:
            raise HTTPException(status_code=401, detail="Invalid session key format.")

        with self._lock:
            self._cleanup_locked(current)
            record = self._keys.get(raw_key_id)
            if not record:
                raise HTTPException(status_code=401, detail="Unknown or expired session key.")
            expected_hash = self._hash_token(raw_key_id, raw_secret)
            if not hmac.compare_digest(expected_hash, record.token_hash):
                raise HTTPException(status_code=401, detail="Session key mismatch.")
            if record.client_id != client_id:
                raise HTTPException(status_code=401, detail="Session key does not match current client.")
            if record.expires_at_s <= current:
                self._keys.pop(raw_key_id, None)
                raise HTTPException(status_code=401, detail="Session key expired.")
            if consume_job_create:
                if record.remaining_job_creates <= 0:
                    raise HTTPException(status_code=429, detail="Job quota exceeded for this session. Generate a new session key to continue.")
                record.remaining_job_creates -= 1
            return SessionPrincipal(
                client_id=record.client_id,
                key_id=record.key_id,
                remaining_job_creates=record.remaining_job_creates,
            )


@dataclass
class JobRecord:
    job_id: str
    file_path: str
    options: dict[str, Any]
    owner_client_id: str
    owner_key_id: str
    status: str = "queued"
    phase: str = "queued"
    progress_percent: int = 0
    message: str = "Queued"
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def touch(
        self,
        *,
        status: str | None = None,
        phase: str | None = None,
        progress: int | None = None,
        message: str | None = None,
    ) -> None:
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
session_keys = SessionKeyManager(
    secret=_session_secret,
    generation_limit=SESSION_KEY_GEN_LIMIT,
    generation_window_seconds=SESSION_KEY_GEN_WINDOW_SECONDS,
    key_ttl_seconds=SESSION_KEY_TTL_SECONDS,
    key_job_limit=SESSION_KEY_JOB_LIMIT,
)
executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="qvk-worker")

_cors_origins_raw = os.environ.get("QVK_CORS_ALLOW_ORIGINS", "").strip()
if _cors_origins_raw:
    _cors_allow_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
else:
    _cors_allow_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Session-Key"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
)


def _allowed_filename(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith((".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".ts", ".3gp"))


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
                raise HTTPException(status_code=413, detail=f"File too large. Maximum upload size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
            handle.write(chunk)
    await file.close()
    if total_bytes < 16:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="File appears to be empty or invalid.")
    return total_bytes


def _client_id_from_request(request: Request) -> str:
    ip = (request.client.host if request.client and request.client.host else "unknown")
    user_agent = request.headers.get("user-agent", "")[:256]
    raw = f"{ip}|{user_agent}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _extract_session_key(request: Request) -> str | None:
    x_session_key = request.headers.get("x-session-key")
    if x_session_key:
        return x_session_key.strip()
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def _authorize_request(request: Request, *, consume_job_create: bool = False) -> SessionPrincipal:
    key_text = _extract_session_key(request)
    if not key_text:
        raise HTTPException(
            status_code=401,
            detail="Missing session key. Generate one at /api/v1/session-key.",
        )
    client_id = _client_id_from_request(request)
    return session_keys.validate_key(key_text, client_id, consume_job_create=consume_job_create)


def _get_owned_job_or_404(job_id: str, principal: SessionPrincipal) -> JobRecord:
    job = store.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.owner_client_id != principal.client_id:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _run_analysis_job(job_id: str) -> None:
    job = store.get(job_id)
    if not job:
        return
    try:
        job.touch(status="processing", phase="extracting_metadata", progress=10, message="Running metadata checks")
        options = AnalysisOptions.from_dict(job.options)
        job.touch(
            status="processing",
            phase="forensic_analysis",
            progress=25,
            message="Analyzing temporal and quality signals",
        )
        if options.enable_advanced_forensics:
            job.touch(
                status="processing",
                phase="advanced_forensics",
                progress=45,
                message="Running advanced forensic checks (compression, ELA, noise, audio spectral, scene analysis)",
            )
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
    return {"status": "ok", "version": "0.3.0", "service": "quevidkit"}


@app.post("/api/v1/session-key")
async def create_session_key(request: Request) -> JSONResponse:
    client_id = _client_id_from_request(request)
    payload = session_keys.issue_key(client_id)
    quota = session_keys.generation_quota(client_id)
    response = JSONResponse(
        status_code=201,
        content={
            "session_key": payload["session_key"],
            "key_id": payload["key_id"],
            "expires_at_utc": payload["expires_at_utc"],
            "expires_in_seconds": payload["expires_in_seconds"],
            "rate_limit": quota,
            "job_quota": payload["job_quota"],
        },
        headers={"Cache-Control": "no-store"},
    )
    response.headers["X-RateLimit-Limit"] = str(quota["limit"])
    response.headers["X-RateLimit-Remaining"] = str(quota["remaining"])
    return response


@app.get("/api/v1/session-key/quota")
async def session_key_quota(request: Request) -> dict[str, Any]:
    client_id = _client_id_from_request(request)
    quota = session_keys.generation_quota(client_id)
    return {"rate_limit": quota}


@app.post("/api/v1/jobs")
async def create_job(
    request: Request,
    file: UploadFile = File(...),
    options: str | None = Form(default=None),
) -> JSONResponse:
    principal = _authorize_request(request, consume_job_create=True)
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")
    if not _allowed_filename(file.filename):
        raise HTTPException(status_code=415, detail="Unsupported video format. Supported formats: MP4, MOV, MKV, AVI, WebM, M4V.")

    parsed_options = _parse_options(options)
    _cleanup_old_uploads()
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    destination = UPLOAD_DIR / f"{job_id}_{Path(file.filename).name}"

    _ = await _save_upload_stream(file, destination)

    job = JobRecord(
        job_id=job_id,
        file_path=str(destination),
        options=parsed_options.__dict__,
        owner_client_id=principal.client_id,
        owner_key_id=principal.key_id,
    )
    store.put(job)
    executor.submit(_run_analysis_job, job_id)
    payload = store.to_status_dict(job)
    payload["session_key_remaining_jobs"] = principal.remaining_job_creates
    return JSONResponse(status_code=202, content=payload)


@app.get("/api/v1/jobs/{job_id}")
async def job_status(request: Request, job_id: str) -> dict[str, Any]:
    principal = _authorize_request(request)
    job = _get_owned_job_or_404(job_id, principal)
    return store.to_status_dict(job)


@app.get("/api/v1/jobs/{job_id}/result")
async def job_result(request: Request, job_id: str) -> dict[str, Any]:
    principal = _authorize_request(request)
    job = _get_owned_job_or_404(job_id, principal)
    if job.status == "failed":
        raise HTTPException(status_code=500, detail=job.error or "Analysis failed")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail="Job not completed yet")
    return {"job_id": job_id, "status": "completed", "result": job.result}


@app.delete("/api/v1/jobs/{job_id}")
async def delete_job(request: Request, job_id: str) -> dict[str, str]:
    principal = _authorize_request(request)
    job = _get_owned_job_or_404(job_id, principal)
    store.delete(job_id)
    try:
        os.remove(job.file_path)
    except OSError:
        pass
    return {"status": "deleted", "job_id": job_id}


def run() -> None:
    import uvicorn

    uvicorn.run(
        "quevidkit.webapp:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

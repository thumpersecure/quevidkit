FROM python:3.11-slim

# ffmpeg provides ffprobe/ffmpeg, which quevidkit requires on PATH for
# container/codec/timing analysis (see README).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

# --- Runtime configuration -------------------------------------------------
# These are sane defaults; override at `docker run -e` / compose time.
# See deploy/.env.example for full documentation of every QVK_* variable.
ENV QVK_UPLOAD_DIR=/data/uploads \
    QVK_MAX_UPLOAD_BYTES=1073741824 \
    QVK_UPLOAD_RETENTION_SECONDS=86400 \
    QVK_KEEP_UPLOADS=0 \
    QVK_SESSION_KEY_TTL_SECONDS=3600 \
    QVK_SESSION_KEY_GEN_LIMIT=10 \
    QVK_SESSION_KEY_GEN_WINDOW_SECONDS=3600 \
    QVK_SESSION_KEY_JOB_LIMIT=10 \
    QVK_CORS_ALLOW_ORIGINS=""

# QVK_SESSION_KEY_SECRET is intentionally left unset here — the app falls
# back to an ephemeral per-process secret if it's not provided. For any
# real deployment, set it explicitly to a long random value so session
# keys survive container restarts and aren't process-specific.

# Non-root runtime user (basic container hardening).
RUN useradd --create-home --shell /usr/sbin/nologin qvk \
    && mkdir -p /data/uploads \
    && chown -R qvk:qvk /app /data
USER qvk

EXPOSE 8000

# NOTE: --workers 1 is required, not a default left unconfigured. The
# session-key store and the job store are both plain in-memory Python
# objects on the FastAPI process. With more than one uvicorn worker,
# requests get load-balanced across separate processes that don't share
# that memory, so a session key minted by one worker looks unknown to
# another ("unknown session key" errors) and job status lookups can
# likewise miss. Scale out with multiple containers/replicas behind a
# load balancer instead of multiple workers in one process.
CMD ["uvicorn", "quevidkit.webapp:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

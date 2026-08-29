from fastapi.testclient import TestClient

import quevidkit.webapp as webapp

# Minimal but real ISO-BMFF ftyp box header: 4-byte size + b"ftyp" + brand.
# Passes _looks_like_supported_video(); a plain b"0" * N payload does not.
FAKE_MP4_HEAD = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41"
FAKE_MP4_BYTES = FAKE_MP4_HEAD + b"\x00" * 16


class _NoopExecutor:
    def submit(self, *_args, **_kwargs) -> None:
        return None


def _make_session_manager(job_limit: int = 10) -> webapp.SessionKeyManager:
    return webapp.SessionKeyManager(
        secret="test-secret",
        generation_limit=10,
        generation_window_seconds=3600,
        key_ttl_seconds=600,
        key_job_limit=job_limit,
    )


def _issue_key(client: TestClient, user_agent: str = "agent-a") -> str:
    response = client.post("/api/v1/session-key", headers={"user-agent": user_agent})
    assert response.status_code == 201
    return response.json()["session_key"]


def _build_client(monkeypatch, tmp_path, *, job_limit: int = 10) -> TestClient:
    monkeypatch.setattr(webapp, "store", webapp.JobStore())
    monkeypatch.setattr(webapp, "session_keys", _make_session_manager(job_limit=job_limit))
    monkeypatch.setattr(webapp, "executor", _NoopExecutor())
    monkeypatch.setattr(webapp, "UPLOAD_DIR", tmp_path)
    return TestClient(webapp.app)


def test_session_key_endpoint_returns_quota_headers(monkeypatch, tmp_path):
    client = _build_client(monkeypatch, tmp_path)
    response = client.post("/api/v1/session-key", headers={"user-agent": "agent-a"})
    assert response.status_code == 201
    assert response.json()["session_key"].startswith("qvk_")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-RateLimit-Limit"] == "10"
    assert response.headers["X-RateLimit-Remaining"] == "9"


def test_create_job_requires_session_key(monkeypatch, tmp_path):
    client = _build_client(monkeypatch, tmp_path)
    files = {"file": ("clip.mp4", b"0" * 32, "video/mp4")}
    response = client.post("/api/v1/jobs", files=files, headers={"user-agent": "agent-a"})
    assert response.status_code == 401
    assert "Missing session key" in response.json()["detail"]


def test_create_job_and_fetch_status_for_same_client(monkeypatch, tmp_path):
    client = _build_client(monkeypatch, tmp_path)
    key = _issue_key(client, user_agent="agent-a")
    files = {"file": ("clip.mp4", FAKE_MP4_BYTES, "video/mp4")}
    create_response = client.post(
        "/api/v1/jobs",
        files=files,
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert create_response.status_code == 202
    payload = create_response.json()
    assert payload["status"] == "queued"
    assert payload["session_key_remaining_jobs"] == 9

    job_id = payload["job_id"]
    status_response = client.get(
        f"/api/v1/jobs/{job_id}",
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert status_response.status_code == 200
    assert status_response.json()["job_id"] == job_id


def test_job_access_rejects_different_client_fingerprint(monkeypatch, tmp_path):
    client = _build_client(monkeypatch, tmp_path)
    key = _issue_key(client, user_agent="agent-a")
    files = {"file": ("clip.mp4", FAKE_MP4_BYTES, "video/mp4")}
    create_response = client.post(
        "/api/v1/jobs",
        files=files,
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    job_id = create_response.json()["job_id"]
    rejected = client.get(
        f"/api/v1/jobs/{job_id}",
        headers={"x-session-key": key, "user-agent": "agent-b"},
    )
    assert rejected.status_code == 401
    assert "does not match current client" in rejected.json()["detail"]


def test_create_job_enforces_session_job_quota(monkeypatch, tmp_path):
    client = _build_client(monkeypatch, tmp_path, job_limit=1)
    key = _issue_key(client, user_agent="agent-a")
    files = {"file": ("clip.mp4", FAKE_MP4_BYTES, "video/mp4")}
    first = client.post(
        "/api/v1/jobs",
        files=files,
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert first.status_code == 202

    second = client.post(
        "/api/v1/jobs",
        files={"file": ("clip2.mp4", FAKE_MP4_BYTES, "video/mp4")},
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert second.status_code == 429
    assert "Job quota exceeded" in second.json()["detail"]


def test_create_job_rejects_extension_only_disguised_file(monkeypatch, tmp_path):
    """A non-video payload renamed to .mp4 must be rejected by content sniffing,
    not just waved through because the filename extension matches."""
    client = _build_client(monkeypatch, tmp_path)
    key = _issue_key(client, user_agent="agent-a")
    files = {"file": ("totally-a-video.mp4", b"MZ" + b"\x00" * 62 + b"this is an exe, not a video", "video/mp4")}
    response = client.post(
        "/api/v1/jobs",
        files=files,
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert response.status_code == 415
    assert "does not match" in response.json()["detail"]


def test_job_store_evicts_oldest_job_past_max_stored_jobs():
    store = webapp.JobStore(max_jobs=2)
    jobs = [
        webapp.JobRecord(job_id=f"job_{i}", file_path=f"/tmp/does-not-exist-{i}", options={}, owner_client_id="c", owner_key_id="k")
        for i in range(3)
    ]
    for job in jobs:
        store.put(job)
    assert store.get("job_0") is None  # oldest evicted
    assert store.get("job_1") is not None
    assert store.get("job_2") is not None

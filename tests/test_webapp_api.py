from fastapi.testclient import TestClient

import quevidkit.webapp as webapp


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
    files = {"file": ("clip.mp4", b"0" * 32, "video/mp4")}
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
    files = {"file": ("clip.mp4", b"0" * 32, "video/mp4")}
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
    files = {"file": ("clip.mp4", b"0" * 32, "video/mp4")}
    first = client.post(
        "/api/v1/jobs",
        files=files,
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert first.status_code == 202

    second = client.post(
        "/api/v1/jobs",
        files={"file": ("clip2.mp4", b"1" * 32, "video/mp4")},
        headers={"x-session-key": key, "user-agent": "agent-a"},
    )
    assert second.status_code == 429
    assert "Job quota exceeded" in second.json()["detail"]

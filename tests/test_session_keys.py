from fastapi import HTTPException

from quevidkit.webapp import SessionKeyManager


def make_manager() -> SessionKeyManager:
    return SessionKeyManager(
        secret="test-secret",
        generation_limit=10,
        generation_window_seconds=3600,
        key_ttl_seconds=600,
        key_job_limit=10,
    )


def test_issue_key_rate_limit_hits_at_ten():
    mgr = make_manager()
    client = "client-a"
    now = 1000.0
    for _ in range(10):
        payload = mgr.issue_key(client, now_s=now)
        assert payload["session_key"].startswith("qvk_")
    try:
        mgr.issue_key(client, now_s=now + 1)
    except HTTPException as exc:
        assert exc.status_code == 429
        return
    assert False, "Expected rate-limit HTTPException"


def test_validate_key_consumes_job_quota():
    mgr = make_manager()
    payload = mgr.issue_key("client-a", now_s=1000.0)
    key = payload["session_key"]
    principal = mgr.validate_key(key, "client-a", consume_job_create=True, now_s=1001.0)
    assert principal.remaining_job_creates == 9


def test_validate_key_rejects_other_client():
    mgr = make_manager()
    payload = mgr.issue_key("client-a", now_s=1000.0)
    key = payload["session_key"]
    try:
        mgr.validate_key(key, "client-b", now_s=1001.0)
    except HTTPException as exc:
        assert exc.status_code == 401
        return
    assert False, "Expected client mismatch rejection"

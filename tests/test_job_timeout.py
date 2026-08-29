import multiprocessing
import time

import quevidkit.webapp as webapp


class _NoopExecutor:
    def submit(self, *_args, **_kwargs) -> None:
        return None


def _make_session_manager() -> webapp.SessionKeyManager:
    return webapp.SessionKeyManager(
        secret="test-secret",
        generation_limit=10,
        generation_window_seconds=3600,
        key_ttl_seconds=600,
        key_job_limit=10,
    )


def _sleep_forever_target(_path: str, _options: dict, result_queue: "multiprocessing.Queue") -> None:
    """Stand-in for _analyze_video_subprocess_target that never returns.
    Must be a real module-level function: multiprocessing's spawn context
    pickles by reference (module + qualname), so it has to be importable in
    a fresh interpreter — a monkeypatched closure or lambda cannot cross
    that boundary, which is exactly why this test exists as its own function.
    """
    time.sleep(30)
    result_queue.put(("ok", {}))  # pragma: no cover - unreachable, killed first


def test_run_analysis_job_kills_process_past_timeout(monkeypatch, tmp_path):
    """A job whose analysis hangs past ANALYSIS_JOB_TIMEOUT_SECONDS must be
    terminated and marked failed within a bounded amount of extra time, not
    left running until the child eventually finishes (or never does)."""
    monkeypatch.setattr(webapp, "store", webapp.JobStore())
    monkeypatch.setattr(webapp, "session_keys", _make_session_manager())
    monkeypatch.setattr(webapp, "executor", _NoopExecutor())
    monkeypatch.setattr(webapp, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(webapp, "ANALYSIS_JOB_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(webapp, "KEEP_UPLOADS", True)
    monkeypatch.setattr(webapp, "_analyze_video_subprocess_target", _sleep_forever_target)

    dummy_video = tmp_path / "job_test_hang.mp4"
    dummy_video.write_bytes(b"\x00\x00\x00\x18ftypisom" + b"\x00" * 16)

    job = webapp.JobRecord(
        job_id="job_test_hang",
        file_path=str(dummy_video),
        options={},
        owner_client_id="c",
        owner_key_id="k",
    )
    webapp.store.put(job)

    started = time.monotonic()
    webapp._run_analysis_job(job.job_id)
    elapsed = time.monotonic() - started

    assert elapsed < 15, "job should be killed shortly after the 1s timeout, not run the full 30s sleep"
    finished = webapp.store.get(job.job_id)
    assert finished.status == "failed"
    assert "time limit" in finished.error


def test_run_analysis_job_completes_normally_within_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(webapp, "store", webapp.JobStore())
    monkeypatch.setattr(webapp, "session_keys", _make_session_manager())
    monkeypatch.setattr(webapp, "executor", _NoopExecutor())
    monkeypatch.setattr(webapp, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(webapp, "ANALYSIS_JOB_TIMEOUT_SECONDS", 30)
    monkeypatch.setattr(webapp, "KEEP_UPLOADS", True)

    dummy_video = tmp_path / "job_test_ok.mp4"
    dummy_video.write_bytes(b"\x00\x00\x00\x18ftypisom" + b"\x00" * 16)

    job = webapp.JobRecord(
        job_id="job_test_ok",
        file_path=str(dummy_video),
        options={"preset": "fast"},
        owner_client_id="c",
        owner_key_id="k",
    )
    webapp.store.put(job)

    webapp._run_analysis_job(job.job_id)

    finished = webapp.store.get(job.job_id)
    # A malformed/empty dummy file won't produce a rich result, but the
    # subprocess must complete and report back, not hang or crash silently.
    assert finished.status in ("completed", "failed")
    assert finished.progress_percent == 100

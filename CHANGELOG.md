# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.2]

- Add PDF metadata endpoint and surface video metadata report
- Fix: `frame_quality_shift` raised a numpy broadcast error on every video (not only odd-width ones) because the 8x8 blockiness measure paired unequal-length column/row slices of the fixed 320x180 analysis frame; the check now runs and has regression tests
- Docs: canonical URLs, host the science PDF on the site (GitHub links 404 while the repo is private), 100dvh body height, version strings aligned
- Ops: systemd unit now has StartLimit (5 starts/5 min), RestartSec=10, an ExecStartPre import check, and OnFailure= ntfy alert, so a broken interpreter/venv fails fast and loudly instead of crash-looping (a Python 3.13->3.14 apt bump left the venv symlink dangling and the service spun ~220k times unnoticed)
- Ops: add `deploy/quevidkit-watchdog.{sh,service,timer}` (1-minute `/api/health` probe, local and via nginx, ntfy on down/recovery), `deploy/rebuild-venv.sh` (self-contained `--copies` venv) and `deploy/requirements.lock`
- Deps: bump minimums to the tested set (fastapi 0.162, uvicorn 0.54, starlette 1.10, numpy 2.5, pypdf 6.21, python-multipart 0.0.33), add upper bounds; pip-audit clean; suite passes on Python 3.13 and 3.14; Dockerfile base moved to python:3.13-slim and installs from the lockfile

## [1.0.1]

- Fix: analysis jobs now run with a hard wall-clock timeout (`QVK_ANALYSIS_JOB_TIMEOUT_SECONDS`, default 600s), enforced by running each job in its own process so a stuck/adversarial upload can be terminated instead of hanging a worker indefinitely
- Fix: the in-memory job store now caps how many jobs it retains (`QVK_MAX_STORED_JOBS`, default 500), evicting the oldest jobs and their upload files instead of growing without bound
- Fix: uploads are now checked against real container magic bytes, not just filename extension, before being accepted or handed to the analysis pipeline

## [1.0.0]

- Add 4 new forensic checks (16-19): sensor noise correlation, AI/deepfake frequency-artifact heuristic, C2PA/provenance manifest detection, container edit-trace deep scan
- Add 2 new in-browser checks and redesign mobile UI for the client-side (GitHub Pages) app
- Redesign self-hosted server UI
- Swap `opencv-python` for `opencv-python-headless` to avoid libGL crashes on headless servers
- Fix upload tempfile race condition (`mktemp` -> `mkstemp`)
- Add Dockerfile and systemd deployment files
- Pin dependency minimum versions in pyproject.toml

## [0.3.0]

- Add corroboration scoring — multiple independent forensic categories must agree for high-probability verdicts
- Add lone-wolf penalty to reduce false positives from single-check findings
- Raise tampered/suspicious probability thresholds
- Add benign-alternative explanations alongside tampering interpretations
- Fix XSS: escape server-supplied strings before `innerHTML` in results UI
- Add advanced forensic checks (deep scan preset)

# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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

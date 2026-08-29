# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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

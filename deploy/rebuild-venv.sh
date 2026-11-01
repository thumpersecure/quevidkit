#!/usr/bin/env bash
# Build a fresh, self-contained venv (python COPIED, not symlinked, so an apt
# python3 default-version bump cannot break it) from the pinned lockfile, then
# smoke-test it. Swap into place by hand (mv venv venv.old; mv venv.new venv).
# Usage: deploy/rebuild-venv.sh /opt/quevidkit/venv.new [python3.13]
set -euo pipefail
DEST=${1:?dest dir}; PY=${2:-python3.13}
cd "$(dirname "$0")/.."
"$PY" -m venv --copies "$DEST"
"$DEST/bin/pip" install -q -U pip
"$DEST/bin/pip" install -q -r deploy/requirements.lock
"$DEST/bin/pip" install -q --no-deps -e .
"$DEST/bin/python" -c "import uvicorn, fastapi, numpy, cv2, quevidkit.webapp; print('venv OK')"

#!/usr/bin/env bash
# quevidkit health watchdog: probes GET /api/health locally and through nginx,
# pushes ntfy on failure (after 2 consecutive misses) and on recovery.
# Token/topic come from /etc/quevidkit-watchdog.env (mode 600, not in repo):
#   NTFY_TOPIC=https://ntfy.sh/<topic>   NTFY_TOKEN=tk_...
# Usage: quevidkit-watchdog.sh [failed|test]
set -uo pipefail
. /etc/quevidkit-watchdog.env
STATE_DIR=/var/lib/quevidkit-watchdog; mkdir -p "$STATE_DIR"
LOG=/var/log/quevidkit-watchdog.log
log(){ echo "$(date '+%F %T') $*" >> "$LOG"; }
notify(){ # title tags priority body
  curl -fsS --max-time 20 -H "Authorization: Bearer ${NTFY_TOKEN}" \
    -H "Title: $1" -H "Tags: $2" -H "Priority: $3" -d "$4" "$NTFY_TOPIC" >>"$LOG" 2>&1 \
    || log "NTFY FAIL ($1)"
}
HOST=$(hostname)

if [ "${1:-}" = failed ]; then
  notify "quevidkit.service FAILED on $HOST" "rotating_light,x" high \
"systemd gave up (start limit hit or hard failure).
$(journalctl -u quevidkit.service -n 8 --no-pager -o cat 2>&1 | tail -8)"
  echo 1 > "$STATE_DIR/alerted"; log "OnFailure alert sent"; exit 0
fi
if [ "${1:-}" = test ]; then
  notify "quevidkit watchdog test" "white_check_mark" default "Test alert from $HOST at $(date)"; exit 0
fi

ok_body='"status":"ok"'
local_resp=$(curl -fsS --max-time 10 http://127.0.0.1:8000/api/health 2>&1) && [[ "$local_resp" == *"$ok_body"* ]] && local_ok=1 || local_ok=0
pub_resp=$(curl -fsS --max-time 10 --resolve api.quevidkit.pro:443:127.0.0.1 https://api.quevidkit.pro/api/health 2>&1) && [[ "$pub_resp" == *"$ok_body"* ]] && pub_ok=1 || pub_ok=0

fails=$(cat "$STATE_DIR/fails" 2>/dev/null || echo 0)
alerted=$(cat "$STATE_DIR/alerted" 2>/dev/null || echo 0)

if [ "$local_ok" = 1 ] && [ "$pub_ok" = 1 ]; then
  echo 0 > "$STATE_DIR/fails"
  if [ "$alerted" = 1 ]; then
    notify "quevidkit RECOVERED on $HOST" "white_check_mark,tada" default "api.quevidkit.pro /api/health OK again at $(date)"
    echo 0 > "$STATE_DIR/alerted"; log "RECOVERED"
  fi
  exit 0
fi

fails=$((fails+1)); echo "$fails" > "$STATE_DIR/fails"
state=$(systemctl is-active quevidkit.service 2>&1)
log "FAIL #$fails local=$local_ok public=$pub_ok unit=$state"

# Self-heal: if the unit hit its start limit (failed), retry at most every 10 min.
if [ "$state" = failed ]; then
  last=$(cat "$STATE_DIR/last_restart" 2>/dev/null || echo 0); now=$(date +%s)
  if [ $((now-last)) -ge 600 ]; then
    echo "$now" > "$STATE_DIR/last_restart"
    systemctl reset-failed quevidkit.service; systemctl start quevidkit.service --no-block
    log "attempted reset-failed + start"
  fi
fi

if [ "$fails" -ge 2 ] && [ "$alerted" = 0 ]; then
  notify "quevidkit DOWN on $HOST" "rotating_light,x" urgent \
"local=$local_ok public(nginx)=$pub_ok unit=$state
$(journalctl -u quevidkit.service -n 6 --no-pager -o cat 2>&1 | tail -6)"
  echo 1 > "$STATE_DIR/alerted"
fi
exit 0

#!/bin/bash
# deka_watchdog.sh — relance delta_client automatiquement quand il se coince.
# (fait ton restart manuel, tout seul). Ne modifie AUCUN code deka.
#
# Auto-detecte le dossier (cwd) et l'interpreteur (exe) du delta_client en cours,
# pour le relancer a l'identique. Fallback: /mnt/DEKA + python py311.
#
# Usage : bash deka_watchdog.sh
#         (options env) FREEZE=60 INTERVAL=5 bash deka_watchdog.sh

INTERVAL=${INTERVAL:-5}          # secondes entre deux verifs
FREEZE=${FREEZE:-60}             # 'endpoints' fige >= FREEZE s => restart
NEED=$(( FREEZE / INTERVAL )); [ "$NEED" -lt 1 ] && NEED=1

detect() {
  local p; p=$(pgrep -f 'delta_client.py' | head -1)
  if [ -n "$p" ]; then
    DDIR=$(readlink /proc/$p/cwd); DEXE=$(readlink /proc/$p/exe)
  fi
  DDIR=${DDIR:-/mnt/DEKA}
  DEXE=${DEXE:-/root/miniconda3/envs/py311/bin/python3.11}
}

get_endpoints() {
python3 - <<'PY' 2>/dev/null
import socket,time
try:
    s=socket.socket(); s.settimeout(4); s.connect(('127.0.0.1',6666))
    s.sendall(b'stats\r\n'); time.sleep(0.5); d=s.recv(4096).decode(); s.close()
    for l in d.splitlines():
        if l.startswith('endpoints'): print(int(l.split(':')[1])); break
    else: print(-1)
except Exception: print(-2)
PY
}

restart_delta() {
  detect
  echo "[$(date +%T)] restart delta_client  (dir=$DDIR exe=$(basename $DEXE))"
  pkill -9 -f 'delta_client.py' 2>/dev/null; sleep 1
  ( cd "$DDIR" && nohup "$DEXE" delta_client.py > /tmp/delta_client.log 2>&1 & )
}

detect
echo "[$(date +%T)] watchdog: dir=$DDIR exe=$DEXE ; restart si 'endpoints' fige ${FREEZE}s"
prev=-99; cnt=0
while true; do
  ep=$(get_endpoints)
  if [ "$ep" = "-2" ]; then echo "[$(date +%T)] deka injoignable"; cnt=0
  elif [ "$ep" -gt 0 ] 2>/dev/null && [ "$ep" = "$prev" ]; then
    cnt=$((cnt+1))
    [ $((cnt % 2)) -eq 0 ] && echo "[$(date +%T)] endpoints=$ep fige ($((cnt*INTERVAL))s/${FREEZE}s)"
    if [ "$cnt" -ge "$NEED" ]; then restart_delta; cnt=0; prev=-99; sleep 3; continue; fi
  else
    cnt=0
  fi
  prev=$ep; sleep "$INTERVAL"
done

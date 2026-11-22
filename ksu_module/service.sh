#!/system/bin/sh
MODDIR=${0%/*}
BIN_DIR="$MODDIR/bin"
STATE_DIR="/data/adb/flclash-tproxy"
HELPER="$BIN_DIR/flclash-helper"
CORE="$BIN_DIR/FlClashCore"
LOG="$STATE_DIR/helper.log"

umask 077
[ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
chmod 755 "$HELPER" "$CORE" 2>/dev/null

# Rotate helper log if > 256KB
if [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 262144 ]; then
    : > "$LOG"
fi

# Stop any previous helper instance cleanly before launching
pkill -f "$HELPER" 2>/dev/null || true
sleep 1

nohup "$HELPER" \
    -listen "127.0.0.1:47890" \
    -core "$CORE" \
    -pkg "com.kestrel.netstat.app" \
    -tproxy-port 7893 \
    -core-log "$STATE_DIR/core.log" \
    >> "$LOG" 2>&1 &

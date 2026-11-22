#!/system/bin/sh
pkill -TERM -f "flclash-helper" 2>/dev/null || true
sleep 1
pkill -KILL -f "flclash-helper" 2>/dev/null || true
pkill -KILL -f "FlClashCore" 2>/dev/null || true

iptables -w 2 -t mangle -D PREROUTING -j FLCLASH_PRE 2>/dev/null || true
iptables -w 2 -t mangle -D OUTPUT -j FLCLASH_OUT 2>/dev/null || true
iptables -w 2 -t mangle -F FLCLASH_PRE 2>/dev/null || true
iptables -w 2 -t mangle -F FLCLASH_OUT 2>/dev/null || true
iptables -w 2 -t mangle -X FLCLASH_PRE 2>/dev/null || true
iptables -w 2 -t mangle -X FLCLASH_OUT 2>/dev/null || true
ip rule del fwmark 0x08000000/0x0f000000 table 233 2>/dev/null || true
ip route flush table 233 2>/dev/null || true

rm -rf /data/adb/flclash-tproxy

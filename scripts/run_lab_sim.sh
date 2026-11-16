#!/bin/bash
# Benign lab simulation: scan, DNS-style queries, HTTP POST transfer. Usage: sudo ./scripts/run_lab_sim.sh
set -u
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
U="${SUDO_USER:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC=10.99.99.1; DST=203.0.113.5
for a in $SRC $DST; do ip -br addr show lo | grep -q "$a/" || ip addr add $a/32 dev lo; done
D="$ROOT/simulations/lab_sim/lab_sim_$(date -u +%Y%m%d_%H%M%S)"; mkdir -p "$D"
python3 "$ROOT/scripts/lab_sim_server.py" $DST > "$D/server.log" 2>&1 &
SPID=$!
sleep 2
tcpdump -U -Z root -i lo -w "$D/capture.pcap" "host $DST" 2> "$D/tcpdump.err" &
TPID=$!
sleep 2
echo "scan start $(date -u +%T)" > "$D/phases.log"
if command -v nmap >/dev/null; then
  nmap -sS -S $SRC -e lo -Pn -n -p 1-1000 $DST > "$D/nmap.out" 2>&1
else
  echo "nmap missing" >> "$D/phases.log"
fi
echo "dns start $(date -u +%T)" >> "$D/phases.log"
runuser -u "$U" -- python3 "$ROOT/scripts/lab_sim_client.py" dns --count 60 >> "$D/client.log" 2>&1
echo "exfil start $(date -u +%T)" >> "$D/phases.log"
runuser -u "$U" -- python3 "$ROOT/scripts/lab_sim_client.py" exfil --count 20 >> "$D/client.log" 2>&1
echo "end $(date -u +%T)" >> "$D/phases.log"
sleep 3
kill -INT $TPID; wait $TPID 2>/dev/null
kill $SPID 2>/dev/null
( cd "$D" && sha256sum capture.pcap > SHA256SUMS )
chown -R "$U" "$ROOT/simulations/lab_sim"
echo "$D"

#!/bin/bash
OUT=evidence/webinvestigation
ZD="$OUT/zeek"
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
{
echo "== T1. text right after /dev/tcp/ in the upload body =="
PY=$(python3 - <<'PYEOF'
import glob, re
for p in sorted(glob.glob("evidence/webinvestigation/objects_stream_650/*")):
    b = open(p, "rb").read()
    i = b.find(b"/dev/tcp/")
    if i >= 0:
        t = b[i+9:i+49]
        print("raw=" + repr(t))
        m = re.search(rb"(\d{1,3}(?:\.\d{1,3}){3})\D{0,3}(\d{1,5})?", t)
        print("ip=" + (m.group(1).decode() if m else "none"))
        print("port=" + (m.group(2).decode() if m and m.group(2) else "none"))
        break
else:
    print("marker not found")
PYEOF
)
echo "$PY"
IP=$(echo "$PY" | sed -n 's/^ip=//p')
if [ -n "$IP" ] && [ "$IP" != none ]; then
  echo "== T2. any frame with $IP in this PCAP =="
  echo -n "frames: "; tshark -r "$PCAP" -Y "ip.addr==$IP" -T fields -e frame.number 2>/dev/null | wc -l
  echo -n "conn.log lines: "; grep -c -F "$IP" "$ZD/conn.log"
else
  echo "== T2. skipped: no IP parsed =="
fi
echo "== T3. connections originated by the web server =="
zeek-cut id.orig_h < "$ZD/conn.log" | grep -c '^73.124.22.98$'
} 2>&1 | tee "$OUT/summary7.txt"

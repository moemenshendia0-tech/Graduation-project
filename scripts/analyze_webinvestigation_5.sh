#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
OUT=evidence/webinvestigation
ZD="$OUT/zeek"
RUN=simulations/lab_beacon/lab_beacon_20261102_211623
hhmmss() { date -u -d "@${1%.*}" +%T; }
unhex() { tr -d ':' | python3 -c "import sys,binascii;sys.stdout.write(binascii.unhexlify(sys.stdin.read().strip()).decode('latin1'))"; }
{
echo "== lab run =="; tail -1 "$RUN/client.log" | cut -c1-110; echo -n "FAILED: "; grep -c FAILED "$RUN/client.log"

echo "== V1. every 302: the request that received it =="
zeek-cut ts method uri status_code < "$ZD/http.log" | awk -F'\t' '$4==302' |
while IFS=$'\t' read -r t m u s; do echo "$(hhmmss $t) $m $u"; done

echo "== V2. responses mentioning the uploaded filename =="
tshark -r "$PCAP" -Y 'http.response && http.file_data contains "NVri2vhp.php"' -T fields -e frame.time_epoch -e http.response.code -e http.content_length |
while IFS=$'\t' read -r t c l; do echo "$(hhmmss $t) status=$c len=$l"; done

echo -n "V3a. requests carrying literal separator zvgjck (expect 0): "
tshark -r "$PCAP" -Y 'http.request && http.request.uri contains "zvgjck"' -T fields -e frame.number | wc -l
echo "V3b. responses containing the separator: structure only, no values"
tshark -r "$PCAP" -Y 'http.response && http.file_data contains "zvgjck"' -T fields -e frame.time_epoch -e http.file_data |
while IFS=$'\t' read -r t hex; do
  body=$(printf '%s' "$hex" | unhex)
  data=$(printf '%s' "$body" | grep -a -o 'qxvbq.*qvpjq' | head -1 | sed 's/^qxvbq//; s/qvpjq$//')
  n=$(printf '%s' "$data" | grep -a -o 'zvgjck' | wc -l)
  lens=$(printf '%s' "$data" | awk -F'zvgjck' '{printf "%d/%d/%d", length($1), length($2), length($3)}')
  echo "$(hhmmss $t) separators=$n first_record_field_lengths(id/pw/user,+-4)=$lens"
done

echo "== V4. uploaded file: Zeek sha256 =="
mkdir -p "$OUT/zeek_hash"
( cd "$OUT/zeek_hash" && zeek -C -r "$PCAP" policy/frameworks/files/hash-all-files >/dev/null 2>&1
  zeek-cut ts filename mime_type seen_bytes sha256 < files.log | grep -F NVri2vhp.php || echo "no hash row" )

echo "== V5. callback target inside upload stream (IP/port only) =="
CB=$(tshark -r "$PCAP" -q -z follow,tcp,ascii,650 2>/dev/null | grep -a -o '/dev/tcp/[0-9A-Za-z.:_-]*/[0-9]*' | sort -u | head -3)
echo "${CB:-none found}"
for x in $CB; do ip=$(echo "$x" | cut -d/ -f3); echo -n "conn.log lines mentioning $ip: "; grep -c -F "$ip" "$ZD/conn.log"; done

echo "== V6. port 443 connections: originator / state =="
zeek-cut id.orig_h id.resp_p conn_state < "$ZD/conn.log" | awk -F'\t' '$2==443' | sort | uniq -c
echo "== V7. weird.log top 5 =="
zeek-cut name < "$ZD/weird.log" | sort | uniq -c | sort -rn | head -5
} 2>&1 | tee "$OUT/summary5.txt"

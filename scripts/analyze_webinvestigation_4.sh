#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
OUT=evidence/webinvestigation
ZD="$OUT/zeek"; SD="$OUT/suricata_rerun_B"
RUN=simulations/lab_beacon/lab_beacon_20261102_211623
hhmmss() { date -u -d "@${1%.*}" +%T; }
{
echo "== lab run health =="
tail -1 "$RUN/client.log" | cut -c1-110; echo -n "FAILED: "; grep -c FAILED "$RUN/client.log"

echo "== A. who originates connections / dst ports =="
zeek-cut id.orig_h < "$ZD/conn.log" | sort | uniq -c | sort -rn
zeek-cut id.resp_p proto < "$ZD/conn.log" | sort | uniq -c | sort -rn | head -5

echo "== B. /admin/uploads and /admin/index.php requests =="
zeek-cut ts method uri response_body_len status_code < "$ZD/http.log" | grep -E '/admin/uploads|/admin/index.php' |
while IFS=$'\t' read -r t m u l s; do echo "$(hhmmss $t) $m ${u:0:160} body=$l status=$s"; done

echo "== C. multipart upload metadata =="
tshark -r "$PCAP" -Y mime_multipart -T fields -e frame.time_epoch -e tcp.stream -e mime_multipart.header.content-disposition -e mime_multipart.header.content-type 2>&1 | cut -c1-300
echo "-- files.log php entries --"
zeek-cut ts mime_type filename seen_bytes < "$ZD/files.log" | grep -iE 'php' | head -10
STREAM=$(tshark -r "$PCAP" -Y mime_multipart -T fields -e tcp.stream 2>/dev/null | head -1)
echo "upload stream: ${STREAM:-none}"
if [ -n "$STREAM" ]; then
  OBJ="$OUT/objects_stream_$STREAM"; mkdir -p "$OBJ"
  tshark -r "$PCAP" -2 -R "tcp.stream==$STREAM" -q --export-objects "http,$OBJ" >/dev/null 2>&1
  echo "exported (hash only, do not open or run):"
  ( cd "$OBJ" && ls -la && sha256sum -- * 2>/dev/null )
fi

echo "== D. selected alerts mapped to requests =="
grep -E 'bash shell piped|Suspicious PHP Code|PHP tags in HTTP POST|exec\) in HTTP Request Body' "$SD/fast.log" |
while read -r line; do
  sig=$(echo "$line" | sed -E 's/.*\[\*\*\] \[[0-9:]+\] (.*) \[\*\*\] \[Class.*/\1/')
  at=$(echo "$line" | awk '{print $1}'); d=${at%%-*}; tm=${at#*-}; tm=${tm%%.*}
  ep=$(date -d "${d:6:4}-${d:0:2}-${d:3:2} $tm +0200" +%s)
  sp=$(echo "$line" | awk '{print $(NF-2)}'); sp=${sp##*:}
  dp=$(echo "$line" | awk '{print $NF}'); dp=${dp##*:}
  echo "[$sig] alert at $(hhmmss $ep) UTC (ports $sp/$dp)"
  zeek-cut ts id.orig_p method uri status_code < "$ZD/http.log" |
    awk -F'\t' -v a="$sp" -v b="$dp" -v e="$ep" '($2==a||$2==b) && ($1-e)<3 && (e-$1)<3' |
    while IFS=$'\t' read -r t p m u s; do echo "     -> $(hhmmss $t) $m ${u:0:300} status=$s"; done
done

echo "== E. 302 Location (path only) =="
tshark -r "$PCAP" -Y 'http.response.code==302' -T fields -e frame.time_epoch -e http.location |
while IFS=$'\t' read -r t l; do echo "$(hhmmss $t) -> ${l%%\?*}"; done

echo "== F. responses containing sqlmap marker (time, status, len; no content) =="
tshark -r "$PCAP" -Y 'http.response && http.file_data contains "qxvbq"' -T fields -e frame.time_epoch -e http.response.code -e http.content_length |
while IFS=$'\t' read -r t c l; do echo "$(hhmmss $t) status=$c len=$l"; done
echo -n "G. requests carrying the literal marker (expect 0): "
tshark -r "$PCAP" -Y 'http.request && http.request.uri contains "qxvbq"' -T fields -e frame.number | wc -l

echo "== H. admin-table UNION request: response size only =="
zeek-cut ts uri response_body_len status_code < "$ZD/http.log" | grep -F 'bookworld_db' |
while IFS=$'\t' read -r t u l s; do echo "$(hhmmss $t) status=$s body_len=$l"; done

echo "== ruleset record =="
echo -n "alert rules: "; grep -c '^alert' /var/lib/suricata/rules/suricata.rules
stat -c 'mtime=%y size=%s' /var/lib/suricata/rules/suricata.rules
} 2>&1 | tee "$OUT/summary4.txt"

#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
OUT=evidence/webinvestigation
RULES=/var/lib/suricata/rules/suricata.rules
{
echo "== time window per tool (UTC) =="
for ua in gobuster sqlmap Firefox Chrome; do
  r=$(awk -F'\t' -v ua="$ua" 'index($7,ua){if(!a)a=$1;b=$1;n++}END{printf "%d %d %d",n,a,b}' "$OUT/http_requests.tsv")
  set -- $r
  echo "$ua  $1 req  $(date -u -d @$2 +%T) -> $(date -u -d @$3 +%T)"
done

echo "== POSTs and their responses (field names only, no values) =="
tshark -r "$PCAP" -Y 'http.request.method=="POST"' -T fields -e frame.time_epoch -e http.request.uri -e urlencoded-form.key -e http.response_in |
while IFS=$'\t' read -r ts uri keys resp; do
  code="no-response"
  [ -n "$resp" ] && code=$(tshark -r "$PCAP" -Y "frame.number==$resp" -T fields -e http.response.code -e http.location -e http.content_length | tr '\t' ' ')
  echo "$(date -u -d @${ts%.*} +%T) POST $uri keys=[$keys] -> $code"
done

echo "== sqlmap markers inside RESPONSE bodies =="
tshark -r "$PCAP" -Y 'http.response && http.file_data contains "qxvbq"' -T fields -e frame.time_epoch -e http.response_for.uri > /tmp/marker.tsv
echo -n "responses containing marker: "; wc -l < /tmp/marker.tsv
cut -c1-140 /tmp/marker.tsv | head -3

echo "== 200 OK paths returned to the scanner (top 25) =="
tshark -r "$PCAP" -Y 'http.response.code==200 && ip.dst==111.224.250.131' -T fields -e http.response_for.uri | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -25
echo "== 500 paths (top 5) =="
tshark -r "$PCAP" -Y 'http.response.code==500' -T fields -e http.response_for.uri | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -5

echo "== 170.40.150.126 requests (epoch, method, uri) =="
awk -F'\t' '$2=="170.40.150.126"' "$OUT/http_requests.tsv" | cut -f1,4,6 | cut -c1-110 | head -30

echo "== suricata inputs =="
suricata -V; ls -la "$RULES" 2>&1
echo -n "lines mentioning sqlmap: ";   grep -ci sqlmap   "$RULES" 2>/dev/null
echo -n "lines mentioning gobuster: "; grep -ci gobuster "$RULES" 2>/dev/null
for V in A B; do
  D="$OUT/suricata_rerun_$V"; mkdir -p "$D"
  EXTRA=(); [ "$V" = B ] && EXTRA=(--set "vars.address-groups.HOME_NET=[73.124.22.0/24]")
  suricata -c /etc/suricata/suricata.yaml -S "$RULES" -k none "${EXTRA[@]}" -r "$PCAP" -l "$D" > "$D/run.out" 2>&1
  echo "== run $V (A: -k none | B: -k none + HOME_NET 73.124.22.0/24): alerts=$(wc -l < "$D/fast.log" 2>/dev/null) =="
  sed -E 's/.*\[\*\*\] \[[0-9:]+\] (.*) \[\*\*\].*/\1/' "$D/fast.log" 2>/dev/null | sort | uniq -c | sort -rn | head -10
done
} 2>&1 | tee "$OUT/summary2.txt"

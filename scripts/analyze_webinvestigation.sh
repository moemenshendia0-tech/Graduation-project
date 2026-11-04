#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
OUT=evidence/webinvestigation
mkdir -p "$OUT"
{
echo "== identity (expected cf31ec09cf2ece5d...) =="
sha256sum "$PCAP"
capinfos -c -u -a -e "$PCAP"
tshark -r "$PCAP" -Y http.request -T fields \
  -e frame.time_epoch -e ip.src -e tcp.stream -e http.request.method \
  -e http.host -e http.request.uri -e http.user_agent > "$OUT/http_requests.tsv"
echo "== request rows =="; wc -l < "$OUT/http_requests.tsv"
echo "== sources ==";  cut -f2 "$OUT/http_requests.tsv" | sort | uniq -c | sort -rn | head
echo "== methods ==";  cut -f4 "$OUT/http_requests.tsv" | sort | uniq -c | sort -rn
echo "== user agents =="; cut -f7 "$OUT/http_requests.tsv" | sort | uniq -c | sort -rn | head -5
echo "== status codes =="
tshark -r "$PCAP" -Y http.response -T fields -e http.response.code | sort | uniq -c | sort -rn | head
echo "== window per source =="
for ip in $(cut -f2 "$OUT/http_requests.tsv" | sort -u); do
  echo -n "$ip  "
  awk -F'\t' -v ip="$ip" '$2==ip{if(!a)a=$1;b=$1;n++}END{printf "%d req  %.0f s\n",n,b-a}' "$OUT/http_requests.tsv"
done
echo "== injection-like URIs (count) =="
grep -ciE "union|select|' or |<script|\.\./" "$OUT/http_requests.tsv"
echo "== injection-like URIs (sample) =="
grep -iE "union|select|' or |<script|\.\./" "$OUT/http_requests.tsv" | cut -f1,2,4,6 | head -10
echo "== POST requests =="
awk -F'\t' '$4=="POST"' "$OUT/http_requests.tsv" | cut -f1,2,5,6 | head -10
echo "== admin/login URIs =="
grep -iE "admin|login" "$OUT/http_requests.tsv" | cut -f1,2,4,6 | head -10
} 2>&1 | tee "$OUT/summary.txt"

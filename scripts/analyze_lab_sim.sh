#!/bin/bash
RUN=$(realpath "$1"); ZD="$RUN/zeek"; SD="$RUN/suricata"; mkdir -p "$ZD" "$SD"
{
capinfos -c -u "$RUN/capture.pcap" | grep -E 'Number|duration'
cat "$RUN/phases.log"; : # Nmap details are reported explicitly below. tail -2 "$RUN/client.log"
( cd "$ZD" && zeek -C -r "$RUN/capture.pcap" 2>&1 | tail -2 )
echo "== conn states =="; zeek-cut conn_state < "$ZD/conn.log" | sort | uniq -c | sort -rn
echo "== nmap =="
echo "configured TCP scan range: 1-1000/tcp"
awk '/^[0-9]+\/tcp[[:space:]]+open/ { print; n++ } END { printf "open TCP ports=%d\\n", n }' "$RUN/nmap.out"
echo "== dns =="; zeek-cut query < "$ZD/dns.log" | awk '{l=length($1); n++; s+=l; if(l>mx)mx=l; if(l>50)lg++; u[$1]=1} END{c=0; for(k in u)c++; printf "queries=%d unique=%d mean_len=%.1f max_len=%d over50=%d\n", n, c, s/n, mx, lg}'
echo "== http =="; zeek-cut method request_body_len < "$ZD/http.log" | awk -F'\t' '$1=="POST"{n++; b+=$2} END{printf "POSTs=%d total_request_bytes=%d\n", n, b}'
echo "== suricata (default HOME_NET) =="
suricata -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules -k none -r "$RUN/capture.pcap" -l "$SD" > "$SD/run.out" 2>&1
echo -n "alerts: "; wc -l < "$SD/fast.log"
sed -E 's/.*\[\*\*\] \[[0-9:]+\] (.*) \[\*\*\].*/\1/' "$SD/fast.log" | sort | uniq -c | sort -rn | head -10
} 2>&1 | tee "$RUN/analysis_summary.txt"

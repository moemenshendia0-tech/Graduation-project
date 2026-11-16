#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
OUT=evidence/webinvestigation
ZD="$OUT/zeek"; SD="$OUT/suricata_rerun_B"
RUN=simulations/lab_beacon/lab_beacon_20261102_211623
mkdir -p "$ZD"
{
echo "== lab run health =="
tail -1 "$RUN/client.log"; echo -n "FAILED: "; grep -c FAILED "$RUN/client.log"
pgrep -af "lab_beacon_client|tcpdump" | cut -c1-70

echo "== zeek on pcap =="
( cd "$ZD" && zeek -C -r "$PCAP" && ls )

echo "== POSTs with status (zeek) =="
zeek-cut ts method uri status_code resp_body_len < "$ZD/http.log" | awk -F'\t' '$2=="POST"' |
while IFS=$'\t' read -r ts m u s l; do echo "$(date -u -d @${ts%.*} +%T) $m $u status=$s body=$l"; done

echo "== status by tool (zeek): count tool status =="
zeek-cut user_agent status_code < "$ZD/http.log" | awk -F'\t' '{t="other"; if($1~/sqlmap/)t="sqlmap"; else if($1~/gobuster/)t="gobuster"; c[t" "$2]++} END{for(k in c)print c[k],k}' | sort -k2,2 -k1,1nr

echo "== sqlmap markers in RESPONSE bodies =="
echo -n "qxvbq: "; tshark -r "$PCAP" -Y 'http.response && http.file_data contains "qxvbq"' -T fields -e tcp.stream | wc -l
echo -n "qvpjq: "; tshark -r "$PCAP" -Y 'http.response && http.file_data contains "qvpjq"' -T fields -e tcp.stream | wc -l

echo "== 200 paths to 111.224.250.131 (top 25) =="
zeek-cut id.orig_h uri status_code < "$ZD/http.log" | awk -F'\t' '$1=="111.224.250.131" && $3==200{split($2,a,"?"); print a[1]}' | sort | uniq -c | sort -rn | head -25
echo "== 500 paths (top 5) =="
zeek-cut uri status_code < "$ZD/http.log" | awk -F'\t' '$2==500{split($1,a,"?"); print a[1]}' | sort | uniq -c | sort -rn | head -5

echo "== suricata run B: all signatures =="
echo -n "total: "; wc -l < "$SD/fast.log"
sed -E 's/.*\[\*\*\] \[[0-9:]+\] (.*) \[\*\*\].*/\1/' "$SD/fast.log" | sort | uniq -c | sort -rn
echo "== scanner/sqlmap sigs =="
grep -iE "sqlmap|gobuster|scanner|nikto|dirbuster" "$SD/fast.log" | cut -c1-200 | head -5
echo "== spotify alert sample =="
grep -i spotify "$SD/fast.log" | cut -c1-220 | head -2
echo "== suricata config/ruleset record =="
grep -n -E "^\s+HOME_NET:" /etc/suricata/suricata.yaml
sha256sum /var/lib/suricata/rules/suricata.rules
suricata-update list-enabled-sources 2>&1 | head -5
} 2>&1 | tee "$OUT/summary3.txt"

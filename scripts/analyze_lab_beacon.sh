#!/bin/bash
# usage: analyze_lab_beacon.sh <run_dir> <rita_dataset> <zeek_out_dir>
RUN=$(realpath "$1"); DS="$2"; ZD=$(realpath -m "$3")
RITA="$HOME/tools/rita-v4.8.2/rita"
CFG="$HOME/projects/soc-migration/.rita-wsl/config.yaml"
[ -f "$RUN/capture.pcap" ] || { echo "no capture"; exit 1; }
ts() { date -u -d "@${1%.*}" '+%F %T'; }
{
echo "== capture identity =="
sha256sum "$RUN/capture.pcap"
capinfos -c -u -a -e "$RUN/capture.pcap" 2>&1
PC="$RUN/capture.pcap"
if tshark -r "$PC" -q 2>&1 | grep -qi 'cut short'; then
  echo "capture truncated at the end; analysing a repaired copy (original untouched)"
  tshark -r "$PC" -F pcap -w "$RUN/capture_repaired.pcap" 2>&1 | tail -1
  PC="$RUN/capture_repaired.pcap"
fi
mkdir -p "$ZD"
echo "== zeek =="
( cd "$ZD" && zeek -C -r "$PC" 2>&1 | tail -3 )
echo -n "connections: "; zeek-cut ts < "$ZD/conn.log" | wc -l
zeek-cut id.orig_h id.resp_h id.resp_p proto < "$ZD/conn.log" | sort | uniq -c
zeek-cut conn_state < "$ZD/conn.log" | sort | uniq -c
F=$(zeek-cut ts < "$ZD/conn.log" | sort -n | head -1); L=$(zeek-cut ts < "$ZD/conn.log" | sort -n | tail -1)
echo "first: $(ts $F) UTC   last: $(ts $L) UTC"
echo "== inter-connection intervals (s) =="
zeek-cut ts < "$ZD/conn.log" | sort -n | awk 'NR>1{d=$1-p;n++;s+=d;ss+=d*d;if(n==1||d<mn)mn=d;if(d>mx)mx=d;if(d>=59&&d<=61)w++}{p=$1}END{m=s/n;printf "n=%d mean=%.3f sd=%.3f min=%.3f max=%.3f within_59_61=%d\n",n,m,sqrt(ss/n-m*m),mn,mx,w}'
echo "== http.log (top 5) =="
zeek-cut method uri status_code response_body_len user_agent < "$ZD/http.log" | sort | uniq -c | sort -rn | head -5
echo "== rita import =="
"$RITA" import -c "$CFG" "$ZD" "$DS" > "$ZD/rita_import.out" 2>&1
head -30 "$ZD/rita_import.out"
"$RITA" list -c "$CFG" | grep -F "$DS"
echo "== show-beacons =="
"$RITA" --config "$CFG" show-beacons "$DS" 2>&1 | head -10
echo "== show-beacons-sni =="
"$RITA" --config "$CFG" show-beacons-sni "$DS" 2>&1 | head -10
} 2>&1 | tee "$RUN/analysis_summary.txt"

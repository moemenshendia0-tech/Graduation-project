#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/netmetria-focused-scenario.pcap"
OUT=evidence/netmetria
ZD="$(pwd)/$OUT/zeek"
mkdir -p "$ZD"
hh() { date -u -d "@${1%.*}" +%T; }
{
echo "== identity (expected 84e66539...) =="
sha256sum "$PCAP"
capinfos -c -u -a -e "$PCAP" 2>&1 | grep -v '^$'
echo "== zeek =="
( cd "$ZD" && zeek -C -r "$PCAP" 2>&1 | tail -3; ls )

echo "== conn: pairs (orig -> resp:port proto, count) =="
zeek-cut id.orig_h id.resp_h id.resp_p proto < "$ZD/conn.log" | sort | uniq -c | sort -rn | head -25
echo "== conn: services =="
zeek-cut service < "$ZD/conn.log" | sort | uniq -c | sort -rn
echo "== conn: states =="
zeek-cut conn_state < "$ZD/conn.log" | sort | uniq -c | sort -rn

echo "== SMB: tree/share mapping (no content) =="
[ -f "$ZD/smb_mapping.log" ] && zeek-cut ts id.orig_h id.resp_h path share_type < "$ZD/smb_mapping.log" | while IFS=$'\t' read -r t a b p s; do echo "$(hh $t) $a -> $b $p ($s)"; done | head -20 || echo "no smb_mapping.log"
echo "== SMB: file actions =="
[ -f "$ZD/smb_files.log" ] && zeek-cut ts id.orig_h id.resp_h action name size < "$ZD/smb_files.log" | while IFS=$'\t' read -r t a b ac n s; do echo "$(hh $t) $a -> $b $ac $n size=$s"; done | head -30 || echo "no smb_files.log"
echo "== DCE/RPC: endpoint/operation by pair =="
[ -f "$ZD/dce_rpc.log" ] && zeek-cut ts id.orig_h id.resp_h endpoint operation < "$ZD/dce_rpc.log" | while IFS=$'\t' read -r t a b e o; do echo "$(hh $t) $a -> $b $e $o"; done | head -40 || echo "no dce_rpc.log"

echo "== HTTP: host/uri groups with interval stats (n>=4) =="
zeek-cut ts id.orig_h host uri status_code < "$ZD/http.log" | sort -k2,2 -k3,3 -k4,4 -k1,1n |
awk -F'\t' '{k=$2" "$3" "$4; if(k==pk){d=$1-pt; n[k]++; s[k]+=d; ss[k]+=d*d} else {c[k]=0} c[k]++; pk=k; pt=$1; st[k]=$5}
END{for(k in c) if(c[k]>=4){m=(n[k]>0)?s[k]/n[k]:0; v=(n[k]>0)?ss[k]/n[k]-m*m:0; if(v<0)v=0; printf "%3d req  mean=%.1fs sd=%.1fs status=%s  %s\n", c[k], m, sqrt(v), st[k], k}}' | sort -rn | head -20

echo "== DNS: record types =="
zeek-cut qtype_name < "$ZD/dns.log" | sort | uniq -c | sort -rn
echo "== DNS: query length stats; queries over 50 chars =="
zeek-cut query < "$ZD/dns.log" | awk '{l=length($0); n++; s+=l; if(l>mx)mx=l; if(l>50)lg++} END{printf "n=%d mean_len=%.1f max_len=%d over50=%d\n", n, s/n, mx, lg}'
echo "== DNS: top 15 queried names =="
zeek-cut query < "$ZD/dns.log" | sort | uniq -c | sort -rn | head -15
echo "== DNS: unique subdomain labels per parent domain (top 5) =="
zeek-cut query < "$ZD/dns.log" | awk -F. 'NF>2{p=$(NF-1)"."$NF; u[p" "$1]=1} END{for(k in u){split(k,a," "); c[a[1]]++} for(p in c) print c[p], p}' | sort -rn | head -5

echo "== TLS: server names =="
[ -f "$ZD/ssl.log" ] && zeek-cut id.orig_h server_name version < "$ZD/ssl.log" | sort | uniq -c | sort -rn | head -12 || echo "no ssl.log"

echo "== suricata (default HOME_NET, same ruleset) =="
SD="$OUT/suricata"; mkdir -p "$SD"
suricata -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules -k none -r "$PCAP" -l "$SD" > "$SD/run.out" 2>&1
echo -n "alerts: "; wc -l < "$SD/fast.log"
sed -E 's/.*\[\*\*\] \[[0-9:]+\] (.*) \[\*\*\].*/\1/' "$SD/fast.log" | sort | uniq -c | sort -rn | head -10
} 2>&1 | tee "$OUT/summary.txt"

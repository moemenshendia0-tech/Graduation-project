#!/bin/bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/netmetria-focused-scenario.pcap"
OUT=evidence/netmetria; ZD="$(pwd)/$OUT/zeek"
{
echo "== N1. svcctl opnums per pair (15=OpenSCManagerW 12=CreateServiceW 19=StartServiceW) =="
tshark -r "$PCAP" -Y svcctl -T fields -e ip.src -e ip.dst -e dcerpc.opnum | sort | uniq -c
echo "== N2. smb2 commands (3=TreeConnect 5=Create 6=Close 8=Read 9=Write 11=Ioctl) =="
tshark -r "$PCAP" -Y smb2 -T fields -e smb2.cmd | sort | uniq -c | sort -rn
echo "== N2b. smb2 writes (src dst length) =="
tshark -r "$PCAP" -Y 'smb2.cmd==9' -T fields -e ip.src -e ip.dst -e smb2.write_length | head -10
echo "== N2c. smb2 responses: cmd + nt_status =="
tshark -r "$PCAP" -Y 'smb2.flags.response==1' -T fields -e smb2.cmd -e smb2.nt_status | sort | uniq -c | sort -rn | head -15
echo "== N3. port 445 connections: dst duration orig_bytes resp_bytes state =="
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes conn_state < "$ZD/conn.log" | awk -F'\t' '$3==445{print $1,$2,$4,$5,$6,$7}'
echo "== N4. kerberos (no account names) =="
zeek-cut request_type service success error_msg < "$ZD/kerberos.log" | sort | uniq -c | sort -rn | head -12
echo -n "unique client principals: "; zeek-cut client < "$ZD/kerberos.log" | sort -u | wc -l
echo "== N5. single HTTP conns from .21 to .10/.15/.20/.30 =="
zeek-cut id.orig_h id.resp_h host uri method status_code user_agent < "$ZD/http.log" | awk -F'\t' '$2 ~ /^10\.42\.20\.(10|15|20|30)$/'
echo "== N5b. arden.local requests: method / user-agent summary =="
zeek-cut host method status_code user_agent < "$ZD/http.log" | awk -F'\t' '$1 ~ /arden.local/' | sort | uniq -c | sort -rn | head -8
echo "== N6. arden.local name resolution =="
zeek-cut query answers < "$ZD/dns.log" | grep arden.local | sort -u
} 2>&1 | tee "$OUT/summary2.txt"

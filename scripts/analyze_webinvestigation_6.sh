#!/bin/bash
OUT=evidence/webinvestigation
OBJ="$OUT/objects_stream_650"
REP=reports/incident_webinvestigation.md
grep -q "Uploaded file: content check" "$REP" && { echo "section already present in $REP; nothing appended"; exit 0; }
[ -f "$REP" ] || { echo "report missing"; exit 1; }
RES=$(python3 - "$OBJ" <<'PYEOF'
import sys, glob, hashlib, re
for p in sorted(glob.glob(sys.argv[1] + "/*")):
    b = open(p, "rb").read()
    i = b.find(b'filename="NVri2vhp.php"')
    if i < 0:
        continue
    nl = b"\r\n" if b"\r\n" in b[:300] else b"\n"
    boundary = b.split(nl, 1)[0]
    s = b.find(nl + nl, i)
    e = b.find(nl + boundary, s + 2 * len(nl)) if s >= 0 else -1
    if s < 0 or e < 0:
        continue
    c = b[s + 2 * len(nl):e]
    names = [b"<?php", b"system", b"shell_exec", b"passthru", b"exec", b"popen", b"proc_open", b"eval", b"base64_decode", b"$_GET", b"$_POST", b"$_REQUEST", b"fsockopen", b"/dev/tcp", b"bash"]
    marks = [m.decode() for m in names if m in c]
    tcp = sorted(set(t.decode() for t in re.findall(rb"/dev/tcp/[\w.:$%{}-]*", b)))
    print("source_file=" + p.split("/")[-1])
    print("request_body_bytes=%d" % len(b))
    print("file_content_bytes=%d" % len(c))
    print("file_content_sha256=" + hashlib.sha256(c).hexdigest())
    print("markers_present=" + (",".join(marks) or "none"))
    print("dev_tcp_target_in_request_body=" + (",".join(tcp) or "none"))
    sys.exit()
print("no_multipart_part_parsed")
PYEOF
)
echo "$RES"
{
echo
echo "## 10. Uploaded file: content check"
echo
echo "Method: the multipart part for NVri2vhp.php was cut out of the exported HTTP request body of TCP stream 650 (scripts/analyze_webinvestigation_6.sh). The file was not opened, executed or stored separately. Zeek files.log had no SHA-256 for it."
echo
echo '```text'
echo "$RES"
echo '```'
echo
echo "Marker names are plain substring matches (for example exec also matches shell_exec). They show that a string is present, not what the code does."
} >> "$REP"
tail -14 "$REP"

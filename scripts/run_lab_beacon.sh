#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
U="${SUDO_USER:-}"
[[ -n "$U" && "$U" != root ]] || {
    echo "Run with sudo from a regular user"
    exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC=10.99.99.1
DST=203.0.113.5
PORT=8000
INTERVAL="${1:-60}"
COUNT="${2:-750}"

[[ "$INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] &&
    awk -v x="$INTERVAL" 'BEGIN {exit !(x > 0)}' ||
    { echo "Interval must be positive"; exit 1; }
[[ "$COUNT" =~ ^[1-9][0-9]*$ ]] ||
    { echo "Count must be a positive integer"; exit 1; }

for a in "$SRC" "$DST"; do
    ip -br addr show lo | grep -q "$a/" || {
        echo "Missing loopback alias $a"
        exit 1
    }
done

RUN="lab_beacon_$(date -u +%Y%m%d_%H%M%S)"
DIR="$ROOT/simulations/lab_beacon/$RUN"
mkdir -p "$DIR/www"
chown "$U":"$(id -gn "$U")" "$DIR" "$DIR/www"
printf 'lab beacon test server\n' > "$DIR/www/index.html"
chown "$U":"$(id -gn "$U")" "$DIR/www/index.html"

SPID=""
TPID=""
CPID=""
START="$(date -u +%FT%TZ)"
FINISHED=0

finish() {
    rc=$?
    (( FINISHED == 0 )) || return "$rc"
    FINISHED=1
    trap - EXIT INT TERM
    set +e

    if [[ -n "$CPID" ]] && kill -0 "$CPID" 2>/dev/null; then
        kill -TERM "$CPID" 2>/dev/null
        wait "$CPID" 2>/dev/null
    fi

    if [[ -n "$TPID" ]] && kill -0 "$TPID" 2>/dev/null; then
        kill -INT "$TPID" 2>/dev/null
        wait "$TPID" 2>/dev/null
    fi

    if [[ -n "$SPID" ]] && kill -0 "$SPID" 2>/dev/null; then
        kill -TERM "$SPID" 2>/dev/null
        wait "$SPID" 2>/dev/null
    fi

    END="$(date -u +%FT%TZ)"
    (
        cd "$DIR"
        shopt -s nullglob
        files=(capture.pcap)
        if ((${#files[@]})); then
            sha256sum "${files[@]}" > SHA256SUMS
        else
            echo "No PCAP files were created" > SHA256SUMS
        fi
    )

    {
        echo "run=$RUN"
        echo "start=$START"
        echo "end=$END"
        echo "exit_code=$rc"
        echo "src=$SRC dst=$DST:$PORT interval=$INTERVAL count=$COUNT"
        echo "server_pid=${SPID:-not_started}"
        echo "tcpdump_pid=${TPID:-not_started}"
        tcpdump --version 2>&1 | head -1
        python3 --version
    } > "$DIR/RUN_INFO.txt"

    chown -R "$U":"$(id -gn "$U")" "$DIR"
    echo "Finished: $DIR"
    return "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Launch the server and retain its PID.
runuser -u "$U" -- python3 "$ROOT/server_keepalive.py" \
    "$DST" "$PORT" > "$DIR/server.log" 2>&1 &
SPID=$!

sleep 2
if ! curl -fsS --max-time 3 --interface "$SRC" \
    "http://$DST:$PORT/" -o /dev/null; then
    echo "Server health check failed"
    exit 1
fi

tcpdump -U -Z root -i lo \
    -w "$DIR/capture.pcap" \
    "host $DST and port $PORT" 2> "$DIR/tcpdump.err" &
TPID=$!

sleep 1
kill -0 "$TPID" 2>/dev/null || {
    echo "tcpdump failed to start"
    exit 1
}

runuser -u "$U" -- python3 "$ROOT/scripts/lab_beacon_client.py" \
    --src "$SRC" --host "$DST" --port "$PORT" \
    --interval "$INTERVAL" --count "$COUNT" \
    --label "$RUN" >> "$DIR/client.log" 2>&1 &
CPID=$!

rc=0
wait "$CPID" || rc=$?
CPID=""
exit "$rc"

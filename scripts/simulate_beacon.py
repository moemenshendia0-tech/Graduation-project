#!/usr/bin/env python3
"""Controlled beacon simulator for the isolated lab.

Generates periodic HTTP GET requests to a server you control, in one of
three modes, to produce comparable traffic for Zeek / Suricata / RITA
analysis. This is NOT a C2 tool: it has no command channel, no payload
execution, and only talks to the host and port you pass in.

Modes:
  A  new-connection : opens a fresh TCP connection every request (urllib)
  B  persistent      : reuses one TCP connection for all requests (keep-alive)
  C  jitter           : like A, but with randomized sleep instead of fixed

Usage:
  python3 simulate_beacon.py --mode A --host 10.x.x.x --port 8000 \
      --interval 60 --count 20 --label s02_modeA

Run the matching capture on the server side (tcpdump) before starting.
"""
import argparse
import http.client
import random
import time
import urllib.request
from datetime import datetime, timezone


def log(label, msg):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{ts}] [{label}] {msg}", flush=True)


def mode_new_connection(host, port, path, interval, count, label):
    """New TCP connection per request (urllib opens and closes each time)."""
    url = f"http://{host}:{port}{path}"
    for i in range(count):
        start = time.monotonic()
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                log(label, f"request {i+1}/{count} status={resp.status}")
        except Exception as exc:
            log(label, f"request {i+1}/{count} FAILED: {exc}")
        elapsed = time.monotonic() - start
        sleep_for = max(0.0, interval - elapsed)
        if i < count - 1:
            time.sleep(sleep_for)


def mode_persistent(host, port, path, interval, count, label):
    """One persistent TCP connection (HTTP/1.1 keep-alive) for all requests."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    for i in range(count):
        start = time.monotonic()
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            log(label, f"request {i+1}/{count} status={resp.status} (persistent)")
        except Exception as exc:
            log(label, f"request {i+1}/{count} FAILED: {exc}, reconnecting")
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(host, port, timeout=5)
        elapsed = time.monotonic() - start
        sleep_for = max(0.0, interval - elapsed)
        if i < count - 1:
            time.sleep(sleep_for)
    conn.close()


def mode_jitter(host, port, path, interval, count, label, jitter_pct=0.2):
    """New connection per request, with randomized interval (+/- jitter_pct)."""
    url = f"http://{host}:{port}{path}"
    spread = interval * jitter_pct
    for i in range(count):
        start = time.monotonic()
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                log(label, f"request {i+1}/{count} status={resp.status}")
        except Exception as exc:
            log(label, f"request {i+1}/{count} FAILED: {exc}")
        elapsed = time.monotonic() - start
        this_interval = interval + random.uniform(-spread, spread)
        sleep_for = max(0.0, this_interval - elapsed)
        if i < count - 1:
            time.sleep(sleep_for)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["A", "B", "C"], required=True,
                    help="A=new-connection, B=persistent, C=jitter")
    p.add_argument("--host", required=True, help="Lab server IP/hostname (your own machine only)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--path", default="/")
    p.add_argument("--interval", type=float, default=60.0, help="seconds between requests")
    p.add_argument("--count", type=int, default=20, help="number of requests to send")
    p.add_argument("--label", default=None, help="log label; defaults to mode+host")
    args = p.parse_args()

    label = args.label or f"mode{args.mode}_{args.host}"
    log(label, f"starting mode={args.mode} host={args.host} port={args.port} "
                f"interval={args.interval}s count={args.count}")

    if args.mode == "A":
        mode_new_connection(args.host, args.port, args.path, args.interval, args.count, label)
    elif args.mode == "B":
        mode_persistent(args.host, args.port, args.path, args.interval, args.count, label)
    elif args.mode == "C":
        mode_jitter(args.host, args.port, args.path, args.interval, args.count, label)

    log(label, "done")


if __name__ == "__main__":
    main()

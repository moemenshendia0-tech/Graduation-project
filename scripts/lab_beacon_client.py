#!/usr/bin/env python3
"""Benign lab beacon client (simulation only).
New TCP connection per request, fixed source IP, fixed interval.
No command channel, no payload execution."""
import argparse
import http.client
import time
from datetime import datetime, timezone


def log(label, msg):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{ts}] [{label}] {msg}", flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--path", default="/")
    p.add_argument("--interval", type=float, default=60.0)
    p.add_argument("--count", type=int, default=750)
    p.add_argument("--label", default="lab_beacon")
    a = p.parse_args()

    log(a.label, f"start src={a.src} dst={a.host}:{a.port} interval={a.interval}s count={a.count}")
    t0 = time.monotonic()
    ok = fail = 0
    for i in range(a.count):
        c = None
        try:
            c = http.client.HTTPConnection(a.host, a.port, timeout=5, source_address=(a.src, 0))
            c.request("GET", a.path, headers={"User-Agent": "lab-beacon-sim/1.0"})
            r = c.getresponse()
            r.read()
            ok += 1
            log(a.label, f"request {i+1}/{a.count} status={r.status}")
        except Exception as exc:
            fail += 1
            log(a.label, f"request {i+1}/{a.count} FAILED: {exc}")
        finally:
            if c:
                c.close()
        if i < a.count - 1:
            delay = t0 + (i + 1) * a.interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    log(a.label, f"done ok={ok} failed={fail}")


if __name__ == "__main__":
    main()

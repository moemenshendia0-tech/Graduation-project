#!/usr/bin/env python3
"""Benign lab traffic generator (simulation only). Random data, own lab addresses only."""
import argparse, base64, http.client, os, random, socket, struct, time


def log(m):
    print(time.strftime("%H:%M:%S", time.gmtime()), m, flush=True)


def qname(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(src, dst, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.settimeout(2)
    pkt = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack(">HH", 1, 1)
    s.sendto(pkt, (dst, 53))
    try:
        s.recvfrom(512)
        ok = 1
    except socket.timeout:
        ok = 0
    s.close()
    return ok


def run_dns(a):
    ok = 0
    for _ in range(10):
        ok += dns_query(a.src, a.dst, random.choice(["www", "mail", "docs", "intranet"]) + ".lab.test")
        time.sleep(0.5)
    log("baseline dns answered %d/10" % ok)
    ok = 0
    for _ in range(a.count):
        raw = base64.b32encode(os.urandom(60)).decode().lower().rstrip("=")
        ok += dns_query(a.src, a.dst, "%s.%s.t.lab.test" % (raw[:50], raw[50:100]))
        time.sleep(0.2)
    log("high-entropy dns answered %d/%d" % (ok, a.count))


def run_exfil(a):
    for i in range(a.count):
        body = os.urandom(a.size)
        c = http.client.HTTPConnection(a.dst, 8080, timeout=10, source_address=(a.src, 0))
        c.request("POST", "/upload", body=body,
                  headers={"User-Agent": "lab-transfer-sim/1.0", "Content-Type": "application/octet-stream"})
        r = c.getresponse()
        r.read()
        c.close()
        log("post %d/%d bytes=%d status=%d" % (i + 1, a.count, a.size, r.status))
        time.sleep(a.interval)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("phase", choices=["dns", "exfil"])
    p.add_argument("--src", default="10.99.99.1")
    p.add_argument("--dst", default="203.0.113.5")
    p.add_argument("--count", type=int, default=60)
    p.add_argument("--size", type=int, default=262144)
    p.add_argument("--interval", type=float, default=3.0)
    a = p.parse_args()
    {"dns": run_dns, "exfil": run_exfil}[a.phase](a)

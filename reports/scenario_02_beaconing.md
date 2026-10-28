# Scenario 02: Controlled Beaconing Simulation (Mode A — new connection per request)

## Objective
Generate synthetic, fully-controlled periodic HTTP traffic (no real malware, no C2
framework) to test whether Zeek + RITA can detect connection-level beaconing, and to
establish — experimentally, not just from the NetSupport case — exactly what conditions
RITA's `show-beacons` needs to produce a result. This scenario deliberately uses the
opposite connection pattern from the NetSupport baseline (new TCP connection per request,
instead of one persistent connection), to give a positive control for the Detection Gap
described in `rita/analysis.md`.

## Environment
- Host: single Ubuntu (WSL2) machine; client and server both run locally
- Network: loopback-only (`lo` interface), using two secondary loopback addresses
  added with `ip addr add` so source and destination are distinct hosts:
  - `10.99.99.1/32` — client, inside RITA's default `InternalSubnets` (`10.0.0.0/8`)
  - `203.0.113.5/32` — server, outside `InternalSubnets` and outside `NeverInclude`
    (TEST-NET-3, RFC 5737, reserved for documentation/testing — never publicly routed)
- This is not a two-machine network test; it validates the detection pipeline
  (Zeek -> RITA) under controlled, repeatable conditions, not network segmentation.
- Tool versions: Zeek 8.0.10, RITA 4.8.2 (`~/tools/rita-v4.8.2/rita`), config
  `~/projects/soc-migration/.rita-wsl/config.yaml` (default `InternalSubnets`, unmodified)
- Client: `scripts/simulate_beacon.py`... superseded for this run by a plain shell loop
  (see Steps) because the script does not yet support binding a source address; the
  script needs a `--bind` option added before reuse (tracked below under Follow-ups).

## Why earlier attempts failed (documented for reproducibility)
Five earlier attempts on this same host (`s02_modeA` through `s02_modeA_v5`) returned
"No results were found" from `show-beacons`. Each failure had a distinct, now-confirmed
cause:

| Attempt | Client/server addresses | Result | Root cause (confirmed) |
|---|---|---|---|
| `s02_modeA`, `_v2` | `127.0.0.1` to `127.0.0.1` / `127.0.0.2` | No host data at all | RITA's filtering code calls Go's `net.IP.IsLoopback()` unconditionally (`util/ip.go`), rejecting any `127.0.0.0/8` address regardless of `InternalSubnets` config. This is hardcoded, not configurable. |
| `s02_modeA_v3` | `203.0.113.1` to `203.0.113.5` | No host data | The project's working config copy (`config-sim.yaml`) had `InternalSubnets` mis-indented as a sibling of `Filtering:` instead of a child of it, so RITA silently fell back to its compiled-in defaults (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and did not recognize `203.0.113.1` as internal. Repeated attempts to patch this file introduced further YAML errors; the file was abandoned rather than reused. |
| `s02_modeA_v4` | `10.99.99.1` to `203.0.113.5`, using the original unmodified `config.yaml` | No host data (only 2 connections captured) | Capture was stopped (Ctrl+C) before the client finished; only 2 of the intended 20 requests were captured. Too few connections for any beacon-timing analysis regardless of RITA's logic. |
| `s02_modeA_v5` | Same as v4, full capture (23/23 connections) | No results, but Host/Beacon analysis ran (no longer silently skipped) | RITA-legacy requires a hardcoded minimum of 23 connections for beacon scoring (`config/static.go`, `DefaultConnectionThresh default:"23"`, enforced as a hard floor via `minBeaconConnectionThreshLimit`). 23 connections sat exactly at or just under the effective threshold after internal de-duplication. |
| **`s02_modeA_v6`** | Same as v5, 35 connections | **Success** | Comfortably above the 23-connection floor. |

## Steps (exact commands run)
```bash
# one-time: give the host two extra loopback addresses to act as distinct internal/external hosts
sudo ip addr add 10.99.99.1/32 dev lo
sudo ip addr add 203.0.113.5/32 dev lo

# server
cd ~/projects/soc-migration/network-traffic-project/simulations/beaconing
python3 -m http.server 8000 --bind 203.0.113.5 &

# capture (separate terminal, started and left running for the full client run)
sudo tcpdump -i lo -w s02_modeA_v6.pcap host 203.0.113.5 and port 8000

# client: 35 requests, 10s apart, bound to the "internal" address
for i in $(seq 1 35); do
  curl -s --interface 10.99.99.1 http://203.0.113.5:8000/ -o /dev/null
  echo "request $i at $(date -u +%H:%M:%S)"
  sleep 10
done
```

```bash
# analysis
cd ~/projects/soc-migration/network-traffic-project
sha256sum simulations/beaconing/s02_modeA_v6.pcap
mkdir -p zeek/s02_modeA_v6 && cd zeek/s02_modeA_v6
/opt/zeek/bin/zeek -C -r ../../simulations/beaconing/s02_modeA_v6.pcap
cd ~/projects/soc-migration/network-traffic-project
rita --config "$HOME/projects/soc-migration/.rita-wsl/config.yaml" import zeek/s02_modeA_v6 s02_modeA_v6
rita --config "$HOME/projects/soc-migration/.rita-wsl/config.yaml" show-beacons s02_modeA_v6
```

Note: `zeek -r` (without `-C`) silently drops all packets with invalid TCP checksums,
which loopback traffic commonly has due to NIC/kernel checksum offloading -- every run in
this scenario used `-C` to disable that check. Without it, `conn.log` shows `orig_pkts=0`
and `duration=-` for every connection, which also produces "no results" for an unrelated
reason.

## Capture
- PCAP: `simulations/beaconing/s02_modeA_v6.pcap`
- SHA-256: `2c512dd9c5a95a2c14e67fd47b5b0660b6ae8dc77fc30c1196858e4121df59f7`
- 35 connections, `10.99.99.1` -> `203.0.113.5:8000`, 10-second interval between requests

## Expected result
With 35 separate TCP connections at a fixed 10-second interval, `show-beacons`
(connection-level analysis) should score this near the maximum, since this is exactly
the pattern it is designed to detect -- new connections at regular intervals -- unlike the
NetSupport case where the periodicity was invisible at the connection level.

## Actual result
Score 1.0 (maximum), Top Interval correctly identified as 10 seconds, all four component
scores (timestamp, datasize, duration, histogram) at or near 1.0.

## RITA output
`show-beacons`: as above. `show-beacons-sni` and `show-useragents` were not checked for
this run (HTTP/plain traffic has no TLS SNI; follow-up optional).

## IOCs
Not applicable -- synthetic, lab-internal traffic only (RFC 5737 TEST-NET-3 destination,
secondary loopback addresses). No indicators to extract.

## Limitations
- This confirms RITA's connection-level detection works correctly and predictably under
  controlled conditions; it does not by itself say anything new about the NetSupport
  traffic beyond what `rita/analysis.md` already states.
- The 23-connection threshold is a hardcoded floor in RITA-legacy, not a tunable
  sensitivity setting exposed in the YAML config in the version used here (4.8.2). Any
  future beacon-style traffic with fewer than ~23 distinct connections will not score,
  regardless of how regular its timing is -- a real limitation of this detection layer,
  not a configuration gap.
- Loopback addresses (`127.0.0.0/8`) can never be used as either endpoint for RITA
  analysis in this version, due to hardcoded `IsLoopback()` filtering. Any future lab
  simulation must use non-loopback addresses (as done here) or a real second host.

## Conclusion
Connection-level beacon detection (`show-beacons`) is confirmed to work correctly when:
(1) traffic uses separate TCP connections rather than one persistent connection,
(2) the connection count is at or above RITA's hardcoded 23-connection floor, and
(3) source/destination addresses fall outside the loopback range and are classified as
internal/external per `InternalSubnets`. This experimentally validates the Detection Gap
already documented from the NetSupport case: NetSupport's single persistent connection
failed condition (1), which is why only `show-beacons-sni` (request-level analysis)
caught it. No malicious activity is implied by this scenario; all traffic was
synthetic and internally generated.

## Follow-ups (not yet done)
- Add a `--bind <source-ip>` option to `scripts/simulate_beacon.py` (currently uses
  `urllib`/`http.client` without source binding) so Mode A/B/C can be run with the
  non-loopback address pattern established here, without falling back to a raw shell loop.
- Run Mode B (persistent connection) with the same non-loopback setup to get a second,
  controlled confirmation that persistent connections reproduce the "No results" pattern
  seen with NetSupport -- this is the comparison that completes the controlled experiment.
- `rita/analysis.md` should link to this file rather than duplicate its troubleshooting
  detail.

# RITA Analysis Record

## Purpose and Scope

This document records previously observed RITA output for the baseline
NetSupport-like traffic investigation. It distinguishes previously imported
Zeek-log results from a fresh end-to-end analysis.

## Tool and Input Provenance

- RITA version: 4.8.2
- Executable: `$HOME/tools/rita-v4.8.2/rita`
- WSL dataset: `soc_wsl_test`, imported on 11 October 2026 from
  `~/projects/soc-migration/zeek-logs`.
- A second dataset, `rita_netsupport`, was restored from the earlier lab.
- The Zeek version used to generate the imported logs has not yet been
  verified from the original generation record.
- Current WSL Zeek version: 8.0.10.
- Fresh Zeek 8.0.10 extraction: completed in `zeek/baseline_zeek810_20261027`.
- Fresh RITA import: completed as `soc_baseline_zeek810_20261027`.
- The new dataset was compared with `rita_netsupport` and `soc_wsl_test`; the
  recorded beacon-SNI row was identical across all three datasets.

## Recorded Commands and Results

### Beacon View

Command:

    rita --config "$HOME/projects/soc-migration/.rita-wsl/config.yaml" show-beacons soc_wsl_test

Recorded result:

    No results were found for soc_wsl_test

### Beacon SNI View

Command:

    rita --config "$HOME/projects/soc-migration/.rita-wsl/config.yaml" show-beacons-sni soc_wsl_test

Recorded output:

    0.968,10.11.26.183,194.180.191.64,58,15882,921162,1,0.915,1,0.957,60

The same output row was recorded for:

    rita --config "$HOME/projects/soc-migration/.rita-wsl/config.yaml" show-beacons-sni rita_netsupport

The raw row is preserved as recorded. This document does not assign meanings
to individual columns beyond the score and IP addresses identified from the
available record.

## Interpretation

- The standard beacon view returned no results for `soc_wsl_test`.
- The beacon-SNI view returned a row with score 0.968 for source
  `10.11.26.183` and destination `194.180.191.64`.
- Identical output from the two datasets does not establish that they were
  independently generated from the same original PCAP.
- The result supports prioritizing the repeated traffic for investigation.
  It does not independently prove malware infection, unauthorized access,
  command and control, or data exfiltration.
- The destination was observed carrying HTTP on TCP port 443 in the existing
  investigation. The command name does not prove that a valid TLS SNI
  hostname was present.

## Outstanding Validation

1. Establish the provenance and Zeek version of the earlier imported datasets,
   if that distinction is needed for the final evidence chain.
2. Correlate the network findings with endpoint process execution, installed
   remote-administration software, persistence artifacts, and host security logs.
3. Preserve the original PCAP and existing datasets.

## Evidence Standard

RITA output is a detection result that must be correlated with underlying
Zeek logs, packet evidence, and other available telemetry. No claim of
confirmed compromise or exfiltration is made from this result alone.

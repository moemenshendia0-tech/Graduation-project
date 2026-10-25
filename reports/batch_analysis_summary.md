# Batch PCAP Analysis Summary

> Generated from local TShark, Zeek and Suricata outputs.
> Alerts and indicators require investigation; absence of alerts does not prove benign traffic.

## 2026-08-09-traffic-analysis-exercise

### SHA-256
```text
0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170  2026-08-09-traffic-analysis-exercise.pcap
```

### Protocol hierarchy (TShark)
```text

===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:22473 bytes:15647786
  eth                                    frames:22473 bytes:15647786
    ip                                   frames:22387 bytes:15644174
      udp                                frames:1508 bytes:681159
        dhcp                             frames:8 bytes:2826
        llmnr                            frames:6 bytes:450
        dns                              frames:474 bytes:66012
        cldap                            frames:70 bytes:17942
        nbns                             frames:44 bytes:4804
        nbdgm                            frames:142 bytes:33710
          smb                            frames:142 bytes:33710
            mailslot                     frames:142 bytes:33710
              browser                    frames:142 bytes:33710
        ntp                              frames:8 bytes:1296
        quic                             frames:750 bytes:553627
          quic                           frames:7 bytes:7937
        mdns                             frames:6 bytes:492
      igmp                               frames:18 bytes:996
      tcp                                frames:20850 bytes:14959853
        ldap                             frames:383 bytes:148923
          ldap                           frames:22 bytes:31372
        http                             frames:330 bytes:248997
          data-text-lines                frames:95 bytes:68940
          json                           frames:4 bytes:2895
            data-text-lines              frames:2 bytes:2313
          urlencoded-form                frames:113 bytes:125965
            http                         frames:64 bytes:67835
          media                          frames:38 bytes:20825
          data                           frames:1 bytes:1144
        nbss                             frames:613 bytes:163397
          smb                            frames:2 bytes:340
          smb2                           frames:611 bytes:163057
            data                         frames:19 bytes:18412
            smb2                         frames:62 bytes:23747
              smb2                       frames:22 bytes:8473
            dcerpc                       frames:68 bytes:18662
              samr                       frames:60 bytes:16334
              srvsvc                     frames:2 bytes:576
            nbss                         frames:1 bytes:318
              smb2                       frames:1 bytes:318
```

### Zeek `http.log`
- Data rows: **176**

Sample records:
```text
1786241253.403397	CDHvyy4QMdcL2ukogk	172.16.8.53	49670	23.33.85.235	80	1	GET	www.msftconnecttest.com	/connecttest.txt	-	1.1	Microsoft NCSI	-	0	22	200	OK	-	-	(empty)	-	-	-	-	-	-	FSxH3i3RMaxczD2vIf	-	text/plain
1786241275.108850	CwLsoTx53rBxrcak6	172.16.8.53	54784	150.171.28.11	80	1	GET	edge.microsoft.com	/browsernetworktime/time/1/current?cup2key=2:q1NNw2dbvkfvYeIJGpAFTFzCEQFA3K690AwAAczlpck&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0	-	0	81	200	OK	-	-	(empty)	-	-	-	-	-	-	Fsqmk62g3jrTSntHf2	'json.txt'	text/plain
1786241293.458817	C8sa7M22TEKXtlFS2d	172.16.8.49	49669	23.220.206.14	80	1	GET	www.msftconnecttest.com	/connecttest.txt	-	1.1	Microsoft NCSI	-	0	22	200	OK	-	-	(empty)	-	-	-	-	-	-	Fe2ovE4EuyNaYev80c	-	text/plain
1786241567.042059	C2zNHLCngH6WvIik1	172.16.8.49	54454	23.47.72.95	80	1	GET	ctldl.windowsupdate.com	/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?836d3a9e2b47a708	-	1.1	Microsoft-CryptoAPI/10.0	-	0	0	304	Not Modified	-	-	(empty)	-	-	-	-	-	-	-	-	-
1786241567.086432	C2zNHLCngH6WvIik1	172.16.8.49	54454	23.47.72.95	80	2	GET	ctldl.windowsupdate.com	/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?85d28798e4cd84ad	-	1.1	Microsoft-CryptoAPI/10.0	-	0	0	304	Not Modified	-	-	(empty)	-	-	-	-	-	-	-	-	-
```

### Zeek `dns.log`
- Data rows: **252**

### Zeek `conn.log`
- Data rows: **659**

### Zeek `ssl.log`
- Data rows: **144**

### Zeek `files.log`
- Data rows: **278**

### Suricata `fast.log`
- Alert lines: **41**

Alert sample:
```text
08/09/2026-05:07:33.439586  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.16.8.53:49670 -> 23.33.85.235:80
08/09/2026-05:08:13.494734  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.16.8.49:49669 -> 23.220.206.14:80
08/09/2026-05:13:26.559349  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54457 -> 172.64.155.76:80
08/09/2026-05:14:31.145228  [**] [1:2027758:5] ET DNS Query for .cc TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 172.16.8.49:50216 -> 172.16.8.8:53
08/09/2026-05:14:26.134824  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54467 -> 146.59.71.167:80
08/09/2026-05:14:50.884545  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54488 -> 38.182.168.246:80
08/09/2026-05:15:18.261317  [**] [1:2221045:1] SURICATA HTTP Unexpected Request body [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 172.16.8.49:54494 -> 45.130.41.161:80
08/09/2026-05:15:22.945821  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54496 -> 45.130.41.161:80
08/09/2026-05:15:46.548985  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54504 -> 172.67.162.153:80
08/09/2026-05:15:46.550129  [**] [1:2221036:1] SURICATA HTTP Response excessive header repetition [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 172.67.162.153:80 -> 172.16.8.49:54504
08/09/2026-05:16:12.278735  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54512 -> 121.54.163.148:80
08/09/2026-05:16:48.904739  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54520 -> 199.192.27.50:80
08/09/2026-05:17:06.632538  [**] [1:2221045:1] SURICATA HTTP Unexpected Request body [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 172.16.8.49:54525 -> 66.29.149.91:80
08/09/2026-05:17:13.492094  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54528 -> 66.29.149.91:80
08/09/2026-05:17:38.678193  [**] [1:2050745:4] ET MALWARE FormBook CnC Checkin (GET) M5 [**] [Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} 172.16.8.49:54542 -> 183.90.186.205:80
```

### Suricata run messages
```text
W: unix-manager: Unix socket: UNIX socket bind(/var/run/suricata/suricata-command.socket) error: Address already in use
```

## 2026-10-01-traffic-analysis-exercise

### SHA-256
```text
287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b  2026-10-01-traffic-analysis-exercise.pcap
```

### Protocol hierarchy (TShark)
```text

===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:42497 bytes:36158156
  eth                                    frames:42497 bytes:36158156
    ip                                   frames:42344 bytes:36148976
      udp                                frames:736 bytes:251699
        dhcp                             frames:4 bytes:1434
        llmnr                            frames:2 bytes:150
        dns                              frames:319 bytes:41647
        cldap                            frames:32 bytes:8207
        nbns                             frames:36 bytes:4049
        nbdgm                            frames:70 bytes:16434
          smb                            frames:70 bytes:16434
            mailslot                     frames:70 bytes:16434
              browser                    frames:70 bytes:16434
        ntp                              frames:8 bytes:1296
        quic                             frames:262 bytes:178236
          quic                           frames:1 bytes:1292
        mdns                             frames:3 bytes:246
      tcp                                frames:41600 bytes:35895788
        ldap                             frames:208 bytes:79912
          ldap                           frames:12 bytes:16980
        nbss                             frames:416 bytes:98435
          smb                            frames:3 bytes:553
          smb2                           frames:413 bytes:97882
            data                         frames:4 bytes:3032
            smb2                         frames:18 bytes:6511
              smb2                       frames:6 bytes:2148
            dcerpc                       frames:134 bytes:32548
              lsarpc                     frames:4 bytes:1052
                _ws.malformed            frames:1 bytes:378
              samr                       frames:112 bytes:26240
        http                             frames:32 bytes:14485
          data-text-lines                frames:3 bytes:1129
          json                           frames:1 bytes:1156
            data-text-lines              frames:1 bytes:1156
          ocsp                           frames:2 bytes:1682
          media                          frames:1 bytes:1010
        dcerpc                           frames:256 bytes:76440
          epm                            frames:40 bytes:10976
          rpc_netlogon                   frames:11 bytes:4306
          drsuapi                        frames:118 bytes:33724
```

### Zeek `http.log`
- Data rows: **16**

Sample records:
```text
1790882847.800770	CzG9kB1vbMgGTQwdo7	10.10.1.128	49670	23.219.87.72	80	1	GET	www.msftconnecttest.com	/connecttest.txt	-	1.1	Microsoft NCSI	-	0	22	200	OK	-	-	(empty)	-	-	-	-	-	-	FM52Kw2aiu2B853WKg	-	text/plain
1790882884.106732	CF9hI11ZGjdzUi0DTg	10.10.1.128	62164	150.171.29.11	80	1	GET	edge.microsoft.com	/browsernetworktime/time/1/current?cup2key=2:O8RYa-06I_3i7skWhHQ_AOmcesBjj_7ZBdPr_gSHFNw&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0	-	0	80	200	OK	-	-	(empty)	-	-	-	-	-	-	FNMqoR1S11AO1m75x3	'json.txt'	text/plain
1790882940.304308	CCimFr41CNfx3pQTnh	10.10.1.128	63969	35.170.55.9	80	1	GET	holtandberyl.com	/prw	-	1.1	curl/8.21.0	-	0	178	301	Moved Permanently	-	-	(empty)	-	-	-	-	-	-	FfFHtVZVyIAp2dpB6	-	text/html
1790882941.737924	C9YoNR2QRN3cSm9dV7	10.10.1.128	63971	35.170.55.9	80	1	GET	holtandberyl.com	/crv	-	1.1	curl/8.21.0	-	0	178	301	Moved Permanently	-	-	(empty)	-	-	-	-	-	-	FVCzJXNAge98Lzsb	-	text/html
1790882942.258994	CMB9p29EvgriPHgXc	10.10.1.128	63973	184.29.91.124	80	1	GET	x2.c.lencr.org	/	-	1.1	Microsoft-CryptoAPI/10.0	-	0	355	200	OK	-	-	(empty)	-	-	-	-	-	-	FDn8qiEHIZk0YVMtj	-	-
```

### Zeek `dns.log`
- Data rows: **172**

### Zeek `conn.log`
- Data rows: **346**

### Zeek `ssl.log`
- Data rows: **91**

### Zeek `files.log`
- Data rows: **24**

### Suricata `fast.log`
- Alert lines: **9**

Alert sample:
```text
10/01/2026-22:27:27.845472  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.10.1.128:49670 -> 23.219.87.72:80
10/01/2026-22:30:36.887372  [**] [1:2016141:9] ET INFO Executable Download from dotted-quad Host [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.10.1.128:63723 -> 107.175.82.242:9000
10/01/2026-22:30:36.887372  [**] [1:2034567:1] ET HUNTING curl User-Agent to Dotted Quad [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.10.1.128:63723 -> 107.175.82.242:9000
10/01/2026-22:30:36.887579  [**] [1:2221036:1] SURICATA HTTP Response excessive header repetition [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 107.175.82.242:9000 -> 10.10.1.128:63723
10/01/2026-22:30:37.031346  [**] [1:2018959:6] ET INFO PE EXE or DLL Windows file download HTTP [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 107.175.82.242:9000 -> 10.10.1.128:63723
10/01/2026-22:30:37.031346  [**] [1:2021076:3] ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 107.175.82.242:9000 -> 10.10.1.128:63723
10/01/2026-22:30:37.031346  [**] [1:2014819:5] ET INFO Packed Executable Download [**] [Classification: Misc activity] [Priority: 3] {TCP} 107.175.82.242:9000 -> 10.10.1.128:63723
10/01/2026-22:30:44.127265  [**] [1:2047866:4] ET INFO Observed Google DNS over HTTPS Domain (dns .google in TLS SNI) [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.10.1.128:63724 -> 8.8.4.4:443
10/01/2026-22:30:55.252914  [**] [1:2210054:1] SURICATA STREAM excessive retransmissions [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 195.63.128.106:443 -> 10.10.1.128:63725
```

### Suricata run messages
```text
W: unix-manager: Unix socket: UNIX socket bind(/var/run/suricata/suricata-command.socket) error: Address already in use
```

## WebInvestigation

### SHA-256
```text
cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647  WebInvestigation.pcap
```

### Protocol hierarchy (TShark)
```text

===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:88862 bytes:28629039
  eth                                    frames:88862 bytes:28629039
    ip                                   frames:88862 bytes:28629039
      udp                                frames:122 bytes:10492
        data                             frames:122 bytes:10492
      tcp                                frames:88740 bytes:28618547
        http                             frames:83418 bytes:28253458
          data-text-lines                frames:41645 bytes:21123081
          png                            frames:3 bytes:746
          urlencoded-form                frames:4 bytes:2633
          mime_multipart                 frames:1 bytes:1122
          image-gif                      frames:6 bytes:3316
        data                             frames:9 bytes:495
===================================================================
```

### Zeek `http.log`
- Data rows: **41709**

Sample records:
```text
1710502799.865245	CG6R7xET41Cniyyng	170.40.150.126	54857	73.124.22.98	80	1	GET	bookworldstore.com	/	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36	-	0	707	200	OK	-	-	(empty)	-	-	-	-	-	-	Fm1V7X2nQ3oxdMgBMk	-	text/html
1710502799.890892	CG6R7xET41Cniyyng	170.40.150.126	54857	73.124.22.98	80	2	GET	bookworldstore.com	/css/style.css	http://bookworldstore.com/	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36	-	0	164	200	OK	-	-	(empty)	-	-	-	-	-	-	FlKeOc3P8SgGAYy6b3	-	text/plain
1710502799.957671	CG6R7xET41Cniyyng	170.40.150.126	54857	73.124.22.98	80	3	GET	bookworldstore.com	/favicon.ico	http://bookworldstore.com/	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36	-	0	1357	200	OK	-	-	(empty)	-	-	-	-	-	-	FgDJ4m1U0DvwwMXQq1	-	image/png
1710502878.586312	CPuaw414hbjuYiebsb	170.40.150.126	54858	73.124.22.98	80	1	GET	bookworldstore.com	/about.php	http://bookworldstore.com/	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36	-	0	583	200	OK	-	-	(empty)	-	-	-	-	-	-	FPm4W04zKgwPf74Zqi	-	text/html
1710502878.605129	CPuaw414hbjuYiebsb	170.40.150.126	54858	73.124.22.98	80	2	GET	bookworldstore.com	/style.css	http://bookworldstore.com/about.php	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36	-	0	138	200	OK	-	-	(empty)	-	-	-	-	-	-	FW6DQmHO1hi04R6p1	-	text/plain
```

### Zeek `conn.log`
- Data rows: **660**

### Zeek `files.log`
- Data rows: **41660**

### Suricata `fast.log`
- Alert lines: **0**

### Suricata run messages
```text
W: unix-manager: Unix socket: UNIX socket bind(/var/run/suricata/suricata-command.socket) error: Address already in use
```

## netmetria-focused-scenario

### SHA-256
```text
84e66539101bcf14d28ca97c26674096f4afc53e9370a5dd0ef77069cdf850e6  netmetria-focused-scenario.pcap
```

### Protocol hierarchy (TShark)
```text

===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:1592 bytes:210234
  eth                                    frames:1592 bytes:210234
    ip                                   frames:1592 bytes:210234
      udp                                frames:316 bytes:28612
        dns                              frames:300 bytes:27172
        ntp                              frames:16 bytes:1440
      tcp                                frames:1276 bytes:181622
        http                             frames:108 bytes:31741
          data-text-lines                frames:22 bytes:5830
          json                           frames:32 bytes:8372
        tls                              frames:210 bytes:51264
        nbss                             frames:200 bytes:46957
          smb2                           frames:200 bytes:46957
            dcerpc                       frames:40 bytes:9860
              srvsvc                     frames:10 bytes:2420
              svcctl                     frames:10 bytes:2280
            data                         frames:5 bytes:1390
===================================================================
```

### Zeek `http.log`
- Data rows: **54**

Sample records:
```text
1788357960.687279	CANT3d21BvGXVgcj9j	10.42.10.21	64113	198.18.42.52	80	1	GET	www.msftconnecttest.com	/connecttest.txt	-	1.1	Microsoft NCSI	-	0	22	200	OK	-	-	(empty)	-	-	-	-	-	-	FrYrcOJsvN2j7UTtb	-	text/plain
1788357960.756580	CNvY3r3T7Gk6regBlf	10.42.10.22	52146	198.18.42.52	80	1	GET	www.msftconnecttest.com	/connecttest.txt	-	1.1	Microsoft NCSI	-	0	22	200	OK	-	-	(empty)	-	-	-	-	-	-	FFTICu4jyjwB5D06v7	-	text/plain
1788357968.334262	CK9a0I28EdVeIcowGl	10.42.10.21	54936	10.42.20.40	80	1	GET	portal.arden.local	/api/session	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36	-	0	34	200	OK	-	-	(empty)	-	-	-	-	-	-	FwEbM732gAJxE68BX3	-	text/json
1788357990.760901	C1olcwghll29olyPc	10.42.10.22	50352	10.42.20.40	80	1	GET	updates.arden.local	/catalog/v1/current.json	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36	-	0	32	200	OK	-	-	(empty)	-	-	-	-	-	-	FI6QRVnjXsleY9ku9	-	text/json
1788358011.298854	CoRxlZMIXt3TqIll1	10.42.10.21	52633	198.18.42.52	80	1	GET	www.msftconnecttest.com	/connecttest.txt	-	1.1	Microsoft NCSI	-	0	22	200	OK	-	-	(empty)	-	-	-	-	-	-	F5xhbV2LeAaD5XdtZb	-	text/plain
```

### Zeek `dns.log`
- Data rows: **150**

### Zeek `conn.log`
- Data rows: **260**

### Zeek `ssl.log`
- Data rows: **28**

### Zeek `files.log`
- Data rows: **59**

### Suricata `fast.log`
- Alert lines: **22**

Alert sample:
```text
09/02/2026-17:06:00.823863  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:52146 -> 198.18.42.52:80
09/02/2026-17:08:02.699692  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:56084 -> 198.18.42.52:80
09/02/2026-17:06:00.755888  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:64113 -> 198.18.42.52:80
09/02/2026-17:06:51.738819  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:53385 -> 198.18.42.52:80
09/02/2026-17:09:39.703227  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:64635 -> 198.18.42.52:80
09/02/2026-17:11:58.529243  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:51498 -> 198.18.42.52:80
09/02/2026-17:06:51.366598  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:52633 -> 198.18.42.52:80
09/02/2026-17:07:57.722477  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:64896 -> 198.18.42.52:80
09/02/2026-17:12:46.084802  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:63212 -> 198.18.42.52:80
09/02/2026-17:12:46.401274  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:65291 -> 198.18.42.52:80
09/02/2026-17:12:04.683847  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:58719 -> 198.18.42.52:80
09/02/2026-17:09:40.064974  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:62887 -> 198.18.42.52:80
09/02/2026-17:09:56.137415  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.22:52038 -> 198.18.42.52:80
09/02/2026-17:10:00.228531  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:53041 -> 198.18.42.52:80
09/02/2026-17:15:13.078748  [**] [1:2031071:5] ET INFO Microsoft Connection Test [**] [Classification: Misc activity] [Priority: 3] {TCP} 10.42.10.21:62459 -> 198.18.42.52:80
```

### Suricata run messages
```text
W: unix-manager: Unix socket: UNIX socket bind(/var/run/suricata/suricata-command.socket) error: Address already in use
```

# Week 2: Protocol Analysis & Anomaly Identification

## Executive Summary
Network traffic analysis was conducted on `2026-01-31-traffic-analysis-exercise.pcap` (`51,181` packets) using **Wireshark**, **Zeek**, and **Suricata**. The investigation identified a confirmed **Win32/Lumma Stealer** infection on internal host **`10.1.21.58`** (`DESKTOP-ES9F3ML`), characterized by cleartext HTTP victim fingerprinting, high-frequency TLS C2 beaconing, and `~2.06 MB` of outbound data exfiltration.

## Key Findings
- **Infected Host:** `10.1.21.58` (`DESKTOP-ES9F3ML` / `win11office.com`)
- **Primary C2 & Exfiltration:** `whitepepper.su` (`153.92.1.49`) over ports `80` (HTTP) and `443` (TLSv1.3)
- **High-Frequency Beaconing:** 16 TLS `Client Hello` connections to `whitepepper.su` with ~0.70s–1.0s intervals
- **Large Outbound Transfers:** `2,060,468 bytes` (~2.06 MB) exfiltrated across three TLS sessions (`1,419,610`, `387,597`, and `253,261` bytes)
- **DNS Tunneling:** Absent (all queries used standard `A`, `HTTPS`, `SRV`, and `PTR` record types)
- **Unusual Ports:** Absent (all network communications utilized standard protocol ports)

## Repository Contents
- `Week2_Report.pdf` — Complete technical analysis report with embedded visual evidence.
- `IOCs/iocs.csv` — Verified Indicators of Compromise (IPs, domains, and C2 URLs).
- `Logs/` — Suricata `fast.log` and Zeek protocol logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `smb_files.log`, `smb_mapping.log`).
- `Evidence/suspicious_traffic.pcap` — Extracted PCAP containing only malicious C2 and staging traffic.
- `Evidence/screenshots/` — Supporting Wireshark and Suricata terminal screenshots.

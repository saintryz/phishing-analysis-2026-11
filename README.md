# DFIR Case Studies

Digital forensics and incident response write-ups by **Ahmed Jamalallail**. Each case covers scope and method, limitations, a timeline, findings, a MITRE ATT&CK mapping, IOCs and recommendations.

Raw evidence (emails, network captures, images) is never published. It contains personal data of the people involved; only SHA-256 hashes are included, so copies shared privately can be verified against each report. Names and identifying details of the organisations involved are redacted.

| Date | Case | Type | Key techniques | IOCs |
|---|---|---|---|---|
| 2026-11 | [Compromised executive mailbox: DocuSign credential phishing](2026-11-phishing-m365/) | Phishing / BEC | T1586.002, T1566.002, T1497.001 | [CSV](2026-11-phishing-m365/iocs.csv) · [STIX 2.1](2026-11-phishing-m365/iocs.stix.json) |

All reports are `TLP:CLEAR` unless marked otherwise. IOC files contain live (not defanged) values for import into security tools: do not open them in a browser.

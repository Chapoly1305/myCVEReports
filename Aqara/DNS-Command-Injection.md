# CVE-2025-65292

Command injection vulnerability in Aqara Hub devices (Camera Hub G3, Hub M2, and Hub M3) allows attackers to execute arbitrary commands with root privileges through malicious domain names.

**Keywords:** Command Injection, Remote Code Execution, DNS

## Description
A command injection vulnerability was discovered in the ha_master component of Aqara Hub devices. The vulnerability stems from improper input sanitization when processing stored domain names in DNS lookups. Attackers can exploit this flaw to execute arbitrary shell commands with root-level privileges. The following function offset is based on Aqara Camera Hub G3 - Firmware 4.1.9_0027.

**Command Injection Through Stored Domain Name**
Camera Hub G3, Hub M2, and Hub M3. The dns_nslookup function (0x2233F4) uses popen() to execute nslookup commands without input filtering. When the target server is unreachable, the stored domain name from persist.app.country_domain is passed directly to popen() for connectivity testing, allowing command injection through any shell separator.

## Test Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26
- **Aqara Hub M2** - Firmware 4.3.6_0027
  - ha_master: f7d23419ea73bbe29ada6423ac98f9edfa96c6acf72c5b7f3571389214f52072
- **Aqara Hub M3** - Firmware 4.3.6_0025
  - ha_master: 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510

## Analysis
**CVSS:3.1 7.3 High**

CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H

This vulnerability allows attacker with write permission to unauthenticated remote code execution with root privileges.

## Timeline
- **July 3, 2025**: Reported to Aqara
- **October 10, 2025**: Vendor responded mitigation schedule.

## Vendor Responded Fix Versions
- Hub M2: Firmware V4.3.8, OTA released August 28, 2025
- Hub M3: Firmware V4.3.8, OTA released August 28, 2025
- Camera Hub G3: Compatible firmware version, OTA released October 20, 2025

## Credits
Junming Chen (George Mason University)
Xiaoyue Ma (George Mason University)
Lannan Lisa Luo, Ph.D. (George Mason University)
Qiang Zeng, Ph.D. (George Mason University)

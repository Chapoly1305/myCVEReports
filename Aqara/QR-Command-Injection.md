# CVE-XXXX-XXXXX

Command injection vulnerabilities in Aqara Camera Hub G3 allow attackers to execute arbitrary commands with root privileges through malicious QR codes during device setup and factory reset.

**Keywords:** Command Injection, Remote Code Execution, QR Code

## Description
Two command injection vulnerabilities were discovered in the ha_master component of Aqara Camera Hub G3 leading to potential attacks. These vulnerabilities stem from improper input sanitization when processing QR code data. Attackers can exploit these flaws to execute arbitrary shell commands with root-level privileges. The following function offsets are based on Aqara Camera Hub G3 - Firmware 4.1.9_0027.

**Sub Issue 1: Improper Input Sanitization in QR Code Processing**
The parse_wifi_qr_data function (offset 0x21aca4) implements a character filter using a blacklist (`$'";|&) but fails to filter newline (0x0A) and carriage return (0x0D) characters. This allows command injection through crafted QR codes during device setup.

**Sub Issue 2: Factory Reset Backdoor with Input Sanitization Bypass**
The factory reset function (sub_21AAF0) lacks input validation for the "ss" and "pp" parameters from QR codes. Commands are constructed via string concatenation and passed to system() without sanitization, enabling arbitrary command execution during factory reset operations.

## Test Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26

## Analysis
**CVSS:3.1 6.6 Medium **

 CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

These vulnerabilities allow unauthenticated remote code execution with root privileges through QR code manipulation during device setup or factory reset.

## Timeline
- **July 3, 2025**: Reported to Aqara
- **October 10, 2025**: Vendor responded mitigation schedule.

## Vendor Responded Fix Versions
- Camera Hub G3: Compatible firmware version, OTA released October 20, 2025

## Credits
Junming Chen (George Mason University)
Xiaoyue Ma (George Mason University)
Lannan Lisa Luo, Ph.D. (George Mason University)
Qiang Zeng, Ph.D. (George Mason University)

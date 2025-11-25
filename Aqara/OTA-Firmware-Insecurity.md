# CVE-2025-65295

Multiple security vulnerabilities in Aqara Hub OTA firmware update process allow signature verification bypass, use weak cryptography, and leak uninitialized memory in firmware headers.

**Keywords:** Firmware Security, Signature Bypass, Weak Cryptography, Memory Disclosure

## Description
Three distinct security issues were discovered in the OTA firmware update mechanism of Aqara Hub devices:

**Sub Issue 1: Signature Verification Bypassed**
The fw_manager.sh script accepts a command-line flag (-n) that completely disables cryptographic signature verification. Analysis of ha_master (firmware V4.3.6_0025, offset 0x2279A0) reveals that signature verification is NEVER invoked - the "-n" flag is always used instead of "-s" flag. This allows installation of unsigned firmware:
```bash
fw_manager.sh -u -n [firmware_path]  # Verification disabled
```

The fw_unpack binary contains logic to skip all cryptographic verification when signature_check_flag == 0.

**Sub Issue 2: Weak Cryptography Implementation**
The firmware signing mechanism uses cryptographically weak algorithms:
- **1024-bit RSA keys**: Considered weak since 2010, vulnerable to factorization attacks
- **MD5 hashing**: Cryptographically broken, used for both firmware manifest and header integrity
- Hardcoded public key in fw_unpack binary (base64 encoded)

**Sub Issue 3: Uninitialized Memory Disclosure**
Firmware headers across multiple versions contain uninitialized stack memory in the model_id field (offset 0x1F). Example from V4.3.6_0025:
```
Model string: "lumi.gateway.acn012" (19 bytes + null)
Leaked data: 0x0b00000000 94b03568 00000000 94b03568
```
The 0x68 suffix pattern indicates stack frame artifacts. Root cause is improper structure initialization in fw_pack before writing headers to files.

## Replication Steps
**For Signature Bypass:**
1. Extract firmware from device or OTA source
2. Modify firmware contents
3. Repackage without valid signature
4. Trigger OTA update process
5. Observe device accepts unsigned firmware via fw_manager.sh -u -n path

**For Memory Disclosure:**
1. Download firmware images from OTA server
2. Extract and examine firmware header at offset 0x1F
3. Parse model_id field (35 bytes)
4. Observe uninitialized memory bytes after null terminator
5. Analyze leaked stack pointers and artifacts

**For Weak Crypto Verification:**
1. Extract hardcoded public key from fw_unpack binary
2. Observe 1024-bit RSA key length
3. Examine firmware manifest and header hash algorithms
4. Confirm MD5 usage despite SHA256 implementation being available

## Test Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26
- **Aqara Hub M2** - Firmware 4.3.6_0027
  - ha_master: f7d23419ea73bbe29ada6423ac98f9edfa96c6acf72c5b7f3571389214f52072
- **Aqara Hub M3** - Firmware 4.3.6_0025
  - ha_master: 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510
  - fw_unpack: 5ab0aef80b8e70284eabc20faed1b50a2362c6cc3892df4f91fe2c85a27613f2

## Analysis
**CVSS:3.1 8.1 High**

Vector: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

**Security Implications:**

*Signature Bypass:*
- Enables installation of malicious firmware
- Complete device compromise possible
- Persistent backdoor installation
- No cryptographic protection despite infrastructure existing

*Weak Cryptography:*
- 1024-bit RSA vulnerable to modern factorization techniques
- MD5 collisions can be generated to bypass integrity checks
- Attacker can forge valid firmware signatures with sufficient computational resources
- Public key hardcoded in binary provides no security through obscurity

*Memory Disclosure:*
- Leaks stack memory contents in firmware headers
- May expose sensitive development environment information
- Stack pointers aid exploitation of other vulnerabilities
- Affects multiple firmware versions consistently

**Hardcoded RSA Public Key:**
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCE9w6rM0ejuwfotGFFW9BitA6SNS9hGcvNVe3w
Qir1gO0HoIEcKsFCwU9h8nos5tezH6ni9UX82cFyiDQhYNKftifZC0dYlDHvRE1+lHUiTY4uozWL
9kLKRIBRNXjFjMMbB6PCG95O9KHRyUA6ueC/JvZ9HCCA94ke61e6P1cXVQIDAQAB
-----END PUBLIC KEY-----
```

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

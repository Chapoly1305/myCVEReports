# CVE-XXXX-XXXXX
Aqara Hub devices fail to validate server certificates in TLS connections for discovery services and CoAP gateway communications, enabling man-in-the-middle attacks on device control and monitoring.

**Keywords:** Certificate Validation Bypass, Man-in-the-Middle, TLS Security Failure, CoAP Security, CWE-295: Improper Certificate Validation

## Description
A certificate validation vulnerability exists in Aqara Hub devices (Camera Hub G3, Hub M2, Hub M3) affecting TLS-protected CoAP communications. However, the CA certificate required for server validation is not configured in the implementation. The code contains a conditional branch that skips certificate verification setup when no CA Cert is present, causing TLS connections to succeed without validation rather than fail.

**Affected Services:**

- Discovery service (port 15050)
- CoAP gateway (port 11121)

**Technical Root Cause:**

**Code Location (M3 Hub v4.3.6_0025):**

- setup_tls_context: 0x39aec
- Conditional branch bypassing verification: 0x39b66
- CA certificate stub function: 0x3a2ac

**Technical Analysis:**

When examining the calling sequence, on_write_event (0x231e50) at offset 0x150 invokes a virtual function from the object's vtable at offset 0x70, passing R1=1 to request SSL verification. This eventually leads to setup_tls_context, where the verification parameter is preserved in register R5:

```
0x39af6: MOV R5, R1 ; Save verification flag
0x39af8: CBZ R3, loc_39B06
```

The critical security decision occurs when the function attempts to retrieve the CA certificate path:

```
0x39b10: LDR R3, [R4] ; Load vtable pointer
0x39b12: MOV R2, #(stub_7+1)
0x39b1a: LDR.W R5, [R3,#0x88] ; Load CA cert function from vtable
0x39b1e: CMP R5, R2 ; Compare with stub
0x39b20: IT EQ
0x39b22: MOVEQ R5, R1 ; If stub, R5 = 0
```

The vtable examination reveals that while the client certificate and private key functions are properly implemented, the CA certificate function at vtable offset 0x88 points to stub_7 (0x3a2ac), which returns NULL, causing R5 to be set to 0.

Subsequently, the code uses this R5 value to determine whether to configure certificate verification:

```
0x39b66: CBZ R5, loc_39B80 ; If no CA cert, skip verification
0x39b68: MOV R1, R5
0x39b6c: BLX SSL_CTX_load_verify_locations
...
0x39b76: MOVS R2, #0 ; NULL callback
0x39b78: MOVS R1, #1 ; SSL_VERIFY_PEER
0x39b7c: BLX SSL_CTX_set_verify_plt
```

Since R5 is 0, the branch at 0x39b66 is taken, completely bypassing both SSL_CTX_load_verify_locations() and SSL_CTX_set_verify(). This results in an SSL context with no peer verification configured, despite the caller's request for verification.

## Replication Steps
1. Aquire CoAP AES Keys (out-of-scope)
2. Set up TCP proxy (e.g., tcpproxy) to simulate CoAP over TLS server
3. Configure proxy with self-signed or invalid certificate
4. Redirect device traffic to proxy server
5. Observe successful TLS connection establishment without certificate validation
6. Intercept and inject CoAP messages (e.g., door unlock commands)

**Proof of Concept:**
We successfully intercepted CoAP messages using [tcpproxy](https://github.com/ickerwx/tcpproxy) with invalid certificates:

- Captured device authentication tokens and session data
- Injected commands including device refresh requests
- Decrypted payload using AES keys obtained from backup data

Example intercepted traffic:
```
< < < < out: aqara_coap
Code: 0x01 (GET)
MID: 0xEE95
Token: 04a6ec555de08233
Option 11 (Uri-Path): //v1.0/lumi/dev/refresh/token
Option 15 (Uri-Query) [AES encrypted]: appId=12345&did=...

> > > > in: aqara_coap
Code: 0x45 (2.05 Content)
MID: 0xECA1
Option 12 (Content-Format): application/json
Payload [AES encrypted]: {"code":0,"result":{...}}
```

## Evaluated Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26
- **Aqara Hub M2** - Firmware 4.3.6_0027
  - ha_master: f7d23419ea73bbe29ada6423ac98f9edfa96c6acf72c5b7f3571389214f52072
- **Aqara Hub M3** - Firmware 4.3.6_0025
  - ha_master: 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510

## Analysis
**CVSS:3.1 7.4 High**

Vector: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

The lack of certificate validation enables man-in-the-middle attacks allowing attackers to:
- Intercept and decrypt portional CoAP communications between devices and cloud, or all messages if also poesing CoAP AES keys
- Inject malicious commands to control smart home devices in real-time
- Replay captured messages to unlock doors or manipulate devices
- Monitor user activity and device states continuously

## Timeline
- **July 3, 2025**: Reported to Aqara
- **October 10, 2025**: Vendor responded mitigation schedule.

## Vendor Responded Fix Versions
- Hub M2: Firmware V4.3.8, OTA deployed on August 28, 2025
- Hub M3: Firmware V4.3.8, OTA deployed on August 28, 2025
- Camera Hub G3: Compatible firmware version, OTA deployed on October 20, 2025

## Credits
Junming Chen (George Mason University)
Xiaoyue Ma (George Mason University)
Lannan Lisa Luo, Ph.D. (George Mason University)
Qiang Zeng, Ph.D. (George Mason University)

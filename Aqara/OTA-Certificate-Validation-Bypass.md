# CVE-XXXX-XXXXX

Aqara Hub devices fail to validate server certificates during HTTPS firmware downloads, allowing man-in-the-middle attackers to intercept firmware update traffic and potentially serve modified firmware files.

**Keywords:** Certificate Validation Bypass, OTA Security, Firmware Update Security, TLS Security Failure, CWE-295: Improper Certificate Validation

## Description
A certificate validation vulnerability exists in Aqara Hub devices (Camera Hub G3, Hub M2, Hub M3) affecting the Over-The-Air (OTA) firmware update process. The firmware download function at address 0x226db0 in the ha_master binary creates an SSL context using TLS_method() and SSL_CTX_new() but does not call SSL_CTX_set_verify() or SSL_CTX_load_verify_locations() to enable certificate validation. 
According to OpenSSL documentation: "*by default, no peer credentials verification is done. This must be explicitly requested.*" The firmware download code creates a TLS connection but does not request certificate verification. This allows the device to accept any certificate presented by the server regardless of its validity, issuer, or whether it matches the expected hostname.

Following is a reconstructed code from the example based on Aqara Hub M3 firmware version 4.3.6_0025:

```c
// Verified in function start_firmware_http_download at 0x226db0
// Line numbers reference decompiled output from IDA Pro

if (is_https) {
    // Line 218: Initialize OpenSSL random number generator
    if (!RAND_poll()) {
        LOG_ERROR("RAND_poll failed");
        cleanup_firmware_context(context, 1);
        return 0;
    }

    // Lines 247-248: Create SSL context using TLS method
    char* method = TLS_method();
    int ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        LOG_ERROR("SSL_CTX_new failed");
        cleanup_firmware_context(context, 1);
        return 0;
    }

    // Line 249: Store SSL context at offset 0xB4 (180 decimal)
    *(context + 180) = ssl_ctx;

    // Line 278: Create SSL object from context
    int ssl = SSL_new(ssl_ctx);

    // Line 279: Set SNI hostname (SSL_CTRL_SET_TLSEXT_HOSTNAME = 55)
    // This informs the server of the hostname but does NOT validate certificates
    SSL_ctrl(ssl, 55, 0, host);

    // Line 280: Create SSL-enabled bufferevent
    bev = bufferevent_openssl_socket_new(base, -1, ssl,
                                         BUFFEREVENT_SSL_CONNECTING,
                                         BEV_OPT_CLOSE_ON_FREE);
}

// MISSING: No calls to SSL_CTX_set_verify() or SSL_CTX_load_verify_locations()
```

The code sets the SNI hostname, which informs the server of the intended hostname but does not validate that the server's certificate is legitimate or matches that hostname.

## Sample Details

**Binary Analysis:**
- **File:** ha_master (Aqara Hub M3 firmware 4.3.6_0025)
- **SHA256:** 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510
- **Vulnerable Function:** start_firmware_http_download
- **Function Address:** 0x226db0
- **Source File:** dfu_task.cpp (lines 266-330 based on debug strings)



## Test Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26
- **Aqara Hub M2** - Firmware 4.3.6_0027
  - ha_master: f7d23419ea73bbe29ada6423ac98f9edfa96c6acf72c5b7f3571389214f52072
- **Aqara Hub M3** - Firmware 4.3.6_0025
  - ha_master: 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510

## Impact Analysis
**CVSS:3.1 7.4 High**

Vector: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

## Timeline
- **July 3, 2025**: Reported to Aqara
- **October 10, 2025**: Vendor responded mitigation schedule.

## Vendor Responded Fixed Versions
- **Hub M2:** Firmware V4.3.8 (released August 28, 2025)
- **Hub M3:** Firmware V4.3.8 (released August 28, 2025)
- **Camera Hub G3:** Fixed version released October 20, 2025

## Credits
Junming Chen (George Mason University)
Xiaoyue Ma (George Mason University)
Lannan Lisa Luo, Ph.D. (George Mason University)
Qiang Zeng, Ph.D. (George Mason University)

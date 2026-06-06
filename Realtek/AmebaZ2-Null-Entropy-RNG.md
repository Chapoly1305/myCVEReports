# CVE Pending

Predictable RNG in Realtek AmebaZ2/D Matter SDK caused by `MBEDTLS_TEST_NULL_ENTROPY` enabled in production builds, resulting in deterministic cryptographic output across all affected devices.

**Keywords:** Insecure Randomness, Weak Entropy, PRNG, Matter, mbedTLS

## Description

A vulnerability was discovered in the Realtek AmebaZ2 and Ameba D Matter SDK (`ambz2_matter`, `ambd_matter`, and upstream `ameba-rtos-matter`). The mbedTLS configuration header enables `MBEDTLS_TEST_NULL_ENTROPY` in production builds alongside `MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES` and `MBEDTLS_NO_PLATFORM_ENTROPY`, which together disable all standard entropy collection paths.

## Affected SDK

| Repository | Branch |
|---|---|
| `ambiot/ambz2_matter` | `release/v1.3` |
| `ambiot/ambz2_matter` | `release/v1.4` (via pinned `ameba-rtos-matter@c671ba5`) |
| `ambiot/ambd_matter` | 9 of 11 branches |
| `Ameba-AIoT/ameba-rtos-matter` | `release/v1.3` and earlier |


## Analysis

**CVSS:3.1 8.1 High**

CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N

All cryptographic operations relying on the DRBG produce predictable output. This affects device attestation key material, CASE session keys, PASE commissioning nonces, and any other randomness drawn through `chip::Crypto::DRBG_get_bytes()`.

## Timeline

- **2025-08-21**: Reported to Realtek
- **2025-08-22 – 2025-08-29**: Vendor patches merged across all affected repositories
- **2025-09-12**: Reported to CSA SIRT
- **2025-09-15**: CSA acknowledged

## Vendor Fix

Realtek commented out `MBEDTLS_TEST_NULL_ENTROPY` and enabled `CONFIG_ENABLE_MATTER_PRNG=1` by default. 

| Repository | Branch | Commit |
|---|---|---|
| `ambiot/ambz2_matter` | `release/v1.3` | `c9755794` |
| `ambiot/ambd_matter` | `release/v1.3` | `a6fef74f` |
| `Ameba-AIoT/ameba-rtos-matter` | `release/v1.3` | `9ba91d56` |

## Credits

Junming Chen (George Mason University)

Lannan Lisa Luo, Ph.D. (George Mason University)

Qiang Zeng, Ph.D. (George Mason University)

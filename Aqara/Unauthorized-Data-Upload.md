# CVE-XXXX-XXXXX

Aqara Hub devices automatically collect and upload sensitive user data without disclosure or consent.

**Keywords:** Privacy Violation, Unauthorized Data Collection, Data Exfiltration

## Description
Aqara Hub products (M2 Hub, M3 Hub, Camera Hub G3) automatically upload configuration data to AWS servers through an undisclosed "hub_backup" process. This occurs daily without user consent or disclosure in the Privacy Notice, user cannot disable such upload. The uploaded data includes:
- Device IDs and passwords
- Wireless network identifiers (SSIDs and BSSIDs) that can be used to geolocate users' physical addresses
- Device CoAP encryption keys that remain valid after factory resets
- Complete device configurations and paired device information
- System properties and storage files
- Zigbee coordinator information and configurations
- Device pairings and security keys
- HomeKit Accessory Protocol (HAP) data
- User account data and automation rules

## Replication Steps
1. Set up Aqara Hub on local network
2. Monitor network traffic to regional AWS servers (e.g., aiot-common-usa.s3.us-west-2.amazonaws.com)
3. Observe daily automated uploads containing sensitive configuration data
4. Note that device owners cannot disable this upload

## Test Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26
- **Aqara Hub M2** - Firmware 4.3.6_0027
  - ha_master: f7d23419ea73bbe29ada6423ac98f9edfa96c6acf72c5b7f3571389214f52072
- **Aqara Hub M3** - Firmware 4.3.6_0025
  - ha_master: 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510

## Analysis
**CVSS:3.1 8.6 High**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N
This design issue has impacts on privacy. It violates data minimization principles by collecting unnecessary security information, and may violate ePrivacy Directive Article 5(3) requiring explicit consent for data storage. Information collected includes WiFi network identifiers and existing network credentials. BSSID enables physical location tracking. A device-persistent CoAP AES key is also backed up. When migrating a device, the new device can recover this key from downloaded content, allowing impersonation and MITM attacks against the device that is backed up.


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

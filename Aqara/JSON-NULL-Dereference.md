# CVE-XXXX-XXXXX

Widespread NULL pointer dereference vulnerabilities in Aqara Hub JSON processing enable denial-of-service attacks through malformed JSON inputs.

**Keywords:** Denial of Service, NULL Pointer Dereference, JSON Parsing

## Description
Critical NULL pointer dereference vulnerabilities exist throughout the ha_master codebase in Aqara Hub devices. The application uses a ported JsonCpp library (version <0.8) with function get_json_field_or_null (0x32C78) that correctly returns NULL for missing JSON fields, but calling code systematically fails to validate returned pointers before dereferencing them.

**Sub Issue 1: JSON Field Access Without Validation**
The get_json_field_or_null function calls Json_Value_unified_member_access (0x32AE8) with get-or-create mode set to 0, which returns NULL for non-existent fields. However, application code passes these potentially NULL pointers directly to functions like convert_value_to_string (0x2C91C), causing segmentation faults.

**Affected Functions:**
- build_device_configuration_json (0x428BC)
- handle_cloud_message (0x2046E4)
- handle_json_message (0x2248B4)
- process_battery_monitoring (0x45740)

**Commonly accessed fields without validation:**
- "name", "data", "did", "res", "token", "cmd", and others

**Sub Issue 2: strtol NULL Pointer Dereference**
The CoAP RX Discovery Handler function (0x216C44) contains a NULL pointer vulnerability when parsing CoAP payloads. When parsing comma-separated values (IP address and port), if the port token is NULL, it is passed directly to strtol() without validation:

```c
v14 = strtok(dest, ",");      // Parse IP (discarded)
v15 = strtok(0, ",");          // Parse port - CAN BE NULL
v18 = strtol(v15, 0, 10);      // CRASH: No NULL check
```

## Replication Steps
**For JSON Field Dereference:**
1. Establish CoAP connection to device
2. Send JSON message intentionally missing expected fields (e.g., omit "name" field)
3. Example malformed JSON:
   ```json
   {
     "type": "device_config",
     "did": "lumi.test"
     // "name" field intentionally omitted
   }
   ```
4. Observe application crash due to NULL pointer dereference at offset 0x001D84C4

**For strtol NULL Dereference:**
1. Send malformed CoAP discovery payload with invalid port format
2. Example: IP address without port number: `192.168.1.100,`
3. Observe crash when strtol attempts to parse NULL pointer
4. Can be triggered from remote server sending invalid discovery responses

## Test Products
- **Aqara Camera Hub G3** - Firmware 4.1.9_0027
  - ha_master: f685eb25a115af88a181844a308733f555ad6a787c8bee593f27e583828faf26
- **Aqara Hub M2** - Firmware 4.3.6_0027
  - ha_master: f7d23419ea73bbe29ada6423ac98f9edfa96c6acf72c5b7f3571389214f52072
- **Aqara Hub M3** - Firmware 4.3.6_0025
  - ha_master: 224583b493b27b7070c9f7a7d77d1418a3807af6ea63c497f7ae8bdc45ec3510

## Analysis
**CVSS:3.1 7.5 High**

Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

**Impact:**
- Remote denial-of-service without authentication
- Deterministic crashes on malformed input
- Multiple attack vectors across different components
- Can be triggered from cloud server or via man-in-the-middle
- Affects core functionality including device configuration, cloud messages, and discovery

**Root Cause:**
The vulnerability stems from:
1. Misunderstanding of get_json_field_or_null API contract
2. Systematic lack of NULL pointer validation throughout codebase
3. Copy-paste coding patterns spreading vulnerable code
4. Insufficient input validation on external data sources

**Code Pattern Analysis:**
Vulnerable pattern (widespread):
```c
v13 = get_json_field_or_null(v24, "task");
// No NULL check
sub_2C3E0(v27, v15);  // CRASH if v13 is NULL
```

Correct pattern (rare):
```c
v11 = get_json_field_or_null(v0, "Bindkey");
v12 = json_field_exists(v11);
if (v12) {
    // Safe to use v11
}
```

## Timeline
- **July 3, 2025**: Reported to Aqara
- **October 10, 2025**: Vendor classified as "product optimization suggestion"

## Vendor Responded Fix Versions
This issue is planned to be addressed in future firmware updates as part of product optimization improvements. No specific fix version announced yet.

## Credits
Junming Chen (George Mason University)
Xiaoyue Ma (George Mason University)
Lannan Lisa Luo, Ph.D. (George Mason University)
Qiang Zeng, Ph.D. (George Mason University)

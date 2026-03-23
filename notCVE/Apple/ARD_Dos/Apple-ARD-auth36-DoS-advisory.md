# Apple Remote Desktop auth36 Pre-Authentication Denial of Service Advisory

## Briefing

Apple Remote Desktop, as used by Screen Sharing and Remote Management, is vulnerable to a pre-authentication denial-of-service condition that I confirmed on macOS `15.7` and `26.3`. A malicious unauthenticated network client can send malformed SRP traffic in ARD authentication type `36`, causing the `screensharingd` daemon to enter either a high-CPU loop or a degraded state where new connections are rejected, stall, or time out.

The practical impact is loss of remote access. In affected cases, users may be unable to reach their Apple systems through Screen Sharing even though the daemon may still appear to be running and listening. During testing, the service did not automatically recover simply because the attacker disconnected.

Internet exposure appears significant. Shodan reported more than `54,000` potentially affected active hosts on the Internet. In a `1,000`-host sample, without actively triggering the issue, about `85.5%` appeared affected. Specifically, `948` hosts showed `RFB 003.889`, and `855` completed the ARD Direct-SRP handshake path and returned the expected denial response, indicating the same Apple-style SRP authentication flow.

Apple closed the case and did not classify the behavior as a security issue. I am publishing this information so users and administrators can make informed deployment decisions.

## Technical Details

The bug is a state-machine flaw in `screensharingd` during auth type `36` SRP processing.

An unauthenticated client can:

1. Connect to the Screen Sharing service
2. Complete the RFB version handshake
3. Select ARD auth type `36`
4. Reach the SRP challenge stage
5. Send a malformed SRP message with an inconsistent length/body combination

The core problem is that the daemon can read the SRP framing, detect that the claimed body length does not match the bytes actually available, and return early without fully consuming the malformed message. Even though the parse is incomplete, the connection can still be advanced into later SRP state. Later handling notices an invalid step, but the daemon does not reliably drain the unread bytes or tear down the malformed connection.

This can produce two observable outcomes:

- High-CPU mode: the same unread malformed traffic is handled repeatedly, driving `screensharingd` into a busy loop.
- Degraded-service mode: malformed connections remain attached long enough to poison later connection handling, causing new sessions to fail, stall, or time out even while the daemon remains alive.

The issue is reachable without valid credentials. Testing used invalid usernames and did not require successful authentication.

## Impact

This is not just a single-session instability. The issue can result in unauthenticated denial of service with an optional performance downgrade, and in practice it can prevent large numbers of users from accessing their Apple products through Screen Sharing or Remote Management if exposed services are targeted at scale.

Observed impact included:

- rejection of new Screen Sharing connections
- connection stalls or timeouts
- `screensharingd` stuck in a high-CPU state
- degraded service while the daemon still appeared to be alive
- lack of automatic daemon recovery after the attacking client disconnected

## Suggestions

Users and administrators should reduce exposure immediately if they rely on Screen Sharing or Remote Management.

- Disable Screen Sharing and Remote Management if they are not required.
- Restrict access with a properly configured firewall so the service is reachable only from trusted management hosts or networks.
- Prefer access models where another authenticated channel, such as SSH or a VPN, is established first before Screen Sharing is used.
- Avoid exposing ARD or Screen Sharing directly to the public Internet whenever possible.

## Timeline

- `2026-03-19`: Issue reported to Apple
- `2026-03-23`: Apple closed the case and did not classify it as a security issue

## Related Materials

- Investigation notes: `2026-03-19-screensharingd-auth36-srp-loop.md`
- PoC: `appleauth36_poc.py`
- Short social draft: `social-post.txt`

# Summary

I am investigating a pre-auth denial-of-service issue in Apple Screen Sharing auth type `36` on macOS `15.7.1` build `24G231`, Darwin `24.6.0`. The affected host used in testing was `Alexs-Mac-mini.local`, and the on-host `screensharingd` binary at `/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd` has SHA-256 `29466a68c8482213c809e0fa626d45281ced29d8d9f72a3d48afaddfbe5cab8c`. The analyzed Binary Ninja sample was `screensharingd_arm64e.bndb`, SHA-256 `0c87804f4577617c7e37226a406c0e826654392e3c8ee3e78d5aa53443234d53`. The issue occurs during auth type `36` SRP processing, before successful authentication completes, and it is reachable with an invalid username or password. A malformed SRP message sent after the auth36 challenge can push `screensharingd` into either a noticeable high-CPU failure mode or a silent low-CPU degraded mode. In the high-CPU case, the daemon repeatedly reprocesses unread malformed SRP bytes and can consume multiple cores. In the low-CPU case, the daemon remains alive and listening on port `5900`, malformed viewers remain attached in `ESTABLISHED` or later `CLOSE_WAIT`, and later connection handling becomes degraded even though CPU stays near zero. During live testing, an already-established healthy viewer session could remain connected while malformed viewers were attached. In some low-CPU runs, native Screen Sharing clients still connected; in stronger degraded runs, new PoC or later viewers were rejected before banner or failed to make progress. The low-CPU outcome is therefore a degraded-service state, not always a fully dead service.

The earliest preserved occurrence in the collected logs began at `2026-03-19 01:18:16.912508 -0400` with the sequence `viewerDesiredAuthMethod 36`, `SendSRPChallenge`, `available data 16`, `HandleSRPAuthenticationMessage`, and `SRP invalid step`. That sequence matches the state-machine failure seen in Binary Ninja. In the analyzed `screensharingd` sample, `sub_100013900` is the main auth and viewer-state dispatcher, `sub_1000172d0` is the auth36 SRP challenge and first-message parser, `sub_100031640` is the per-viewer receive loop, `sub_100031d8c` is the follow-on maintenance and teardown path, and `sub_10002edac` is the viewer admission path into shared global viewer state. The bug is not SRP math failure. The bug is that `sub_1000172d0` can read the 4-byte SRP length field and return early when the claimed body length exceeds the bytes actually available, but the malformed SRP body is not fully consumed and the internal SRP step is not advanced correctly. Even so, `sub_100013900` still advances the viewer into the later SRP message-handling state. Later SRP handling then sees an invalid step and returns without draining the unread socket bytes or closing the viewer. After that, `sub_100031640` continues redispatching the same viewer while bytes remain pending, producing the high-CPU spin when teardown does not win first. The same flaw also explains the low-CPU dead-service state: `sub_10002edac` has already admitted malformed viewers into shared daemon state, so the daemon can stay alive and listening while enough poisoned viewers exist that new connections no longer make auth or viewer-setup progress.

The wrongful transition can be summarized as:

```c
viewer = admit_viewer();                   // sub_10002edac

switch (viewer->auth_type) {               // sub_100013900
case AUTH36:
    parse_srp_first_message(viewer);       // sub_1000172d0
    viewer->state = SRP_MESSAGE;           // ==> moved forward even if parse was incomplete
    break;
}

// inside sub_1000172d0
len = read_u32();
if (len > available_bytes()) {
    return;                                // ==> body not consumed, SRP step not truly advanced
}

// later SRP handler
if (viewer->srp_step != 1) {
    log("SRP invalid step");
    return;                                // ==> unread bytes remain queued
}

// receive loop in sub_100031640
while (socket_has_pending_data()) {
    dispatch_viewer(viewer);               // ==> same malformed bytes trigger the same path again
}
```

The key wrongful points are:

- `==>` `sub_1000172d0` returns after consuming only SRP framing, not the malformed body
- `==>` `sub_100013900` advances auth state anyway
- `==>` the invalid-step path returns without draining unread bytes and without closing the viewer
- `==>` `sub_100031640` sees the same bytes pending and redispatches the same broken viewer repeatedly
- `==>` `sub_10002edac` has already inserted malformed viewers into shared global state, which is why the daemon can remain alive but unusable for new viewers

This explains both externally visible outcomes. The high-CPU mode happens when malformed viewers survive inside the runnable unread-bytes receive loop. The low-CPU degraded mode happens when malformed viewers poison shared state but remain attached, closing, or otherwise non-runnable, so CPU stays low while the service becomes unreliable for new connections. Earlier C-based testing showed that smaller staged groups such as `4` or `5` could drive the daemon into the noticeable high-CPU form, while larger staged groups such as `6` or more often produced the silent low-CPU attached-viewer form. The final standalone Python PoC reproduced the low-CPU form cleanly with one script and one command by staging multiple auth36 viewers one by one to challenge-ready state and then sending the malformed SRP payload to all staged sockets together.

# Steps to reproduce
1. Use a host running macOS `15.7.1` build `24G231` with Screen Sharing enabled. The host used in this investigation was `Alexs-Mac-mini.local`, with `screensharingd` SHA-256 `29466a68c8482213c809e0fa626d45281ced29d8d9f72a3d48afaddfbe5cab8c`.
2. Use the standalone PoC at `/Users/alex/apple_vnc_workspace/forensics/appleauth36_poc.py`. The PoC connects over IPv4, performs the RFB handshake, selects auth type `36`, sends the auth36 branch-entry packet, reads the auth36 challenge, stages connections one by one to challenge-ready state, then sends a malformed `16`-byte SRP body to all staged sockets together and holds the sockets open.
3. Run the PoC with an invalid username. Valid credentials are not required. Example:

```sh
python3 /Users/alex/apple_vnc_workspace/forensics/appleauth36_poc.py \
  Alexs-Mac-mini.local \
  --username wronguser \
  --count 4
```

4. To reproduce the low-CPU degraded form with the final standalone PoC, use a staged group such as `4` or `10`, again connecting one by one and then sending together. In the final Python tests, `--count 4` and `--count 10` both reproduced the low-CPU attached-viewer outcome.

# Expected results

After receiving malformed pre-auth auth36 SRP input, `screensharingd` should reject the offending viewer cleanly. The daemon should not advance auth state when the SRP parser has not successfully consumed a valid message, should not leave unread malformed SRP bytes queued on the socket, and should terminate the malformed viewer instead of redispatching it. Existing healthy sessions should continue normally, and new viewers should still be able to connect after the malformed viewer is rejected. CPU usage should remain normal.

# Actual results

After malformed auth36 SRP input, `screensharingd` entered one of two failure modes. In the noticeable high-CPU mode, the daemon repeatedly reprocessed unread malformed SRP bytes, producing approximately one hot loop per affected viewer and reaching roughly `98%`, `176%` to `188%`, `286%`, and up to about `375%` CPU in live testing. In the silent low-CPU degraded mode, the daemon remained near `0%` CPU and continued listening on port `5900`, but malformed viewers remained in `ESTABLISHED` or later `CLOSE_WAIT` and the service became unreliable for later incoming viewers. An already-established healthy viewer session could remain connected while the daemon was already degraded. In some low-CPU runs, native Screen Sharing still connected; in other runs, new PoC or later connections were rejected before banner or failed to make progress. With the final standalone Python PoC, a staged `--count 4` run reproduced the low-CPU form with `4` malformed viewers left `ESTABLISHED`, and a staged `--count 10` run reproduced the same low-CPU form with `10` malformed viewers left `ESTABLISHED`, while `screensharingd` remained at `0%` and continued listening on port `5900`. The preserved unified-log signature of the fault was `viewerDesiredAuthMethod 36`, `SendSRPChallenge`, `available data 16` or later `available data 12`, `HandleSRPAuthenticationMessage`, and `SRP invalid step`, first observed at `2026-03-19 01:18:16.912508 -0400`.

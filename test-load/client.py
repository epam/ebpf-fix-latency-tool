#!/usr/bin/env python3
import socket
import time
import sys

SOH = b"\x01"

def main():
    # Create socket with TCP_NODELAY to send immediately (no Nagle algorithm)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.connect(("192.168.1.74", 8080))
    print("Connected to server (TCP_NODELAY enabled)", flush=True)

    start_time = time.time()

    for i in range(10000):
        clid = f"{i:08d}".encode()
        msg = b"8=FIX.4.4" + SOH + b"35=D" + SOH + b"11=" + clid + SOH

        c.sendall(msg)

        reply = c.recv(2048)
        if not reply:
            print(f"[{i}] ERROR: No reply received!", flush=True)

        if i > 0 and i % 100 == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"[{i}] Sent {i} messages in {elapsed:.1f}s ({rate:.0f} msg/s)", flush=True)

        # Sleep 10ms between messages = ~100 msg/sec
        time.sleep(0.01)

    c.close()

if __name__ == "__main__":
    main()

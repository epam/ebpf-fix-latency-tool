#!/usr/bin/env python3
import socket
import time
import sys

SOH = b"\x01"

def main():
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.connect(("127.0.0.1", 8080))
    print("Connected to server", flush=True)

    for i in range(50000):
        clid = f"{i:08d}".encode()
        msg = b"8=FIX.4.4" + SOH + b"35=D" + SOH + b"11=" + clid + SOH

        if i <= 10 or i % 1000 == 0:
            print(f"[{i}] Sending message with ClOrdID={clid.decode()}, msg_len={len(msg)}", flush=True)
        c.sendall(msg)

        reply = c.recv(2048)
        if reply:
            if i <= 10 or i % 1000 == 0:
                print(f"[{i}] Received reply: len={len(reply)}, data={reply[:50]}", flush=True)
        else:
            print(f"[{i}] ERROR: No reply received!", flush=True)

        if i % 1000 == 0:
            print(f"=== Client sent {i} messages ===", flush=True)
        time.sleep(0.001)  # adjust for load

    c.close()

if __name__ == "__main__":
    main()

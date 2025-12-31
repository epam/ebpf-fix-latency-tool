#!/usr/bin/env python3
import socket
import time
import sys

SOH = b"\x01"

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port]")
        print("  Examples:")
        print(f"    {sys.argv[0]} 127.0.0.1")
        print(f"    {sys.argv[0]} 192.168.1.74 8080")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    # Create socket with TCP_NODELAY to send immediately (no Nagle algorithm)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.connect((host, port))
    print(f"Connected to {host}:{port} (TCP_NODELAY enabled)", flush=True)

    start_time = time.time()

    for i in range(10000):
        clid = f"{i:08d}".encode()
        seqnum = f"{i+1}".encode()
        msg = (b"8=FIX.4.4" + SOH +
               b"49=CLIENT" + SOH +
               b"56=SERVER" + SOH +
               b"50=traderjoe" + SOH +
               b"34=" + seqnum + SOH +
               b"35=D" + SOH +
               b"11=" + clid + SOH +
               b"55=TSLA" + SOH +
               b"54=1" + SOH +         # Side=BUY
               b"38=10" + SOH +        # Quantity=10
               b"44=123.45" + SOH +    # LimitPrice=123.45
               b"1=DogeCoin" + SOH +
               b"100=XNAS" + SOH)

        c.sendall(msg)

        reply = c.recv(2048)
        if not reply:
            print(f"[{i}] ERROR: No reply received!", flush=True)

        if i > 0 and i % 10 == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"[{i}] Sent {i} messages in {elapsed:.1f}s ({rate:.1f} msg/s)", flush=True)

        # Sleep 1 second between messages = 1 msg/sec
        time.sleep(0.25)

    c.close()

if __name__ == "__main__":
    main()

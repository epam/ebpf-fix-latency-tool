#!/usr/bin/env python3
import socket, time, signal, sys

SOH = b"\x01"  # FIX field separator
running = True

def handle_sigint(sig, frame):
    global running
    running = False
    print("\nStopping server...")
signal.signal(signal.SIGINT, handle_sigint)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind(("192.168.1.74", 8080))
    s.listen(1)
    print("Server listening on 192.168.1.74:8080", flush=True)
    conn, addr = s.accept()
    print("Connection from", addr)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    msg_count = 0
    last_print = time.time()
    start = last_print

    while running:
        data = conn.recv(2048)
        if not data:
            print(f"Connection closed by client after {msg_count} messages")
            break

        msg_count += 1

        # Extract Tag 11 (ClOrdID)
        try:
            clid = data.split(b"11=")[1].split(SOH)[0]
        except Exception:
            clid = b""

        # Send simple ExecReport back
        reply = b"8=FIX.4.4" + SOH + b"35=8" + SOH + b"11=" + clid + SOH
        conn.sendall(reply)

        now = time.time()
        if now - last_print >= 1.0:
            elapsed = now - start
            rate = msg_count / elapsed if elapsed > 0 else 0
            print(f"[{elapsed:6.1f}s] total={msg_count:,}  rate={rate:,.0f} msg/s")
            last_print = now

    conn.close()
    s.close()

if __name__ == "__main__":
    main()

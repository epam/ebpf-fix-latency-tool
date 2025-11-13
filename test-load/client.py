#!/usr/bin/env python3
import socket, time

SOH = b"\x01"

def main():
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.connect(("127.0.0.1", 9009))
    print("Connected to server")

    for i in range(10000):
        clid = f"{i:08d}".encode()
        msg = b"8=FIX.4.4" + SOH + b"35=D" + SOH + b"11=" + clid + SOH
        c.sendall(msg)
        _ = c.recv(2048)
        if i % 1000 == 0:
            print(f"Sent {i} messages")
        time.sleep(0.001)  # adjust for load

    c.close()

if __name__ == "__main__":
    main()

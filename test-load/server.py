#!/usr/bin/env python3
import socket

SOH = b"\x01"  # FIX field separator

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind(("127.0.0.1", 9009))
    s.listen(1)
    print("Server listening on 127.0.0.1:9009")
    conn, addr = s.accept()
    print("Connection from", addr)

    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    while True:
        data = conn.recv(2048)
        if not data:
            break

        # Extract ClOrdID (Tag 11) from the inbound FIX message
        cl_part = b""
        try:
            cl_part = data.split(b"11=")[1].split(SOH)[0]
        except Exception:
            pass

        # Build an ExecReport-like outbound message
        reply = b"8=FIX.4.4" + SOH + b"35=8" + SOH + b"11=" + cl_part + SOH
        conn.sendall(reply)

    conn.close()
    s.close()

if __name__ == "__main__":
    main()

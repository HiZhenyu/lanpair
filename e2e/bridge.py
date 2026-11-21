"""A simulated LAN segment: a UDP hub that forwards frames and mirrors them to taps."""

import socket
import sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
nodes, taps = {}, set()
while True:
    data, addr = s.recvfrom(65535)
    head, _, payload = data.partition(b"\n")
    parts = head.decode().split()
    if parts[0] == "HELLO":
        nodes[parts[1]] = addr
        if len(parts) > 2 and parts[2] == "tap":
            taps.add(addr)
        s.sendto(b"OK\n", addr)
    elif parts[0] == "TO":
        sender = next((n for n, a in nodes.items() if a == addr), "?")
        frame = f"FROM {sender} TO {parts[1]}\n".encode() + payload
        if parts[1] in nodes:
            s.sendto(frame, nodes[parts[1]])
        for t in taps:
            if t != addr:
                s.sendto(frame, t)
    elif parts[0] == "QUIT":
        break

"""High-level e2e roles (Host, Device, attacker), each run in its own virtual environment.

The pairing link travels through a shared file, standing in for the QR code on screen.
Every role prints JSON lines that run.py checks.
"""

import json
import socket
import struct
import sys
import time
from pathlib import Path

from lanpair import Device, Host, Identity, PairingOffer, Sealer
from lanpair.pairing import make_request

role, shared = sys.argv[1], Path(sys.argv[2])
APP = "lanpair-e2e"


def out(**kw):
    print(json.dumps({"role": role, **kw}), flush=True)


def wait_file(name, timeout=60):
    path = shared / name
    end = time.time() + timeout
    while not path.exists():
        if time.time() > end:
            raise SystemExit(f"timeout waiting for {name}")
        time.sleep(0.1)
    return path.read_text()


if role == "host":
    with Host("E2E desk", app=APP) as host:
        out(event="start", device_id=host.device_id, port=host.port)
        if not host.devices:
            offer = host.pairing_offer()
            (shared / "offer1.txt").write_text(offer.to_uri())
            joined = host.wait_for_pairing(timeout=60)
            out(event="paired", name=joined.name if joined else None)
            # A second offer, for the attacker to try to lock and then use.
            (shared / "offer2.txt").write_text(host.pairing_offer().to_uri())
        (shared / "host.ready").write_text("1")
        for msg in host.messages():
            if msg.body == "stop":
                break
            out(event="received", size=len(json.dumps(msg.body)), sender=msg.sender.name)
            host.send(msg.sender.device_id, {"echo": msg.body})
        out(event="done", dropped=host.dropped, devices=[d.name for d in host.devices])

elif role == "device":
    with Device("E2E room", app=APP) as dev:
        (shared / "device.id").write_text(dev.device_id)
        if dev.host is None:
            paired = dev.pair(wait_file("offer1.txt"))
            out(event="paired", host=paired.name)
        wait_file("host.ready")
        bodies = json.loads(sys.argv[3])
        for body in bodies:
            dev.send(body)
            reply = dev.receive(timeout=10)
            out(
                event="echo",
                ok=reply is not None and reply.body == {"echo": body},
                size=len(json.dumps(body)),
            )
        if len(sys.argv) > 4:
            wait_file(sys.argv[4])  # let the attacker finish first
        dev.send("stop")
        time.sleep(0.5)

elif role == "attacker":
    me = Identity.generate()
    sealer = Sealer(me)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)

    def answered():
        try:
            sock.recvfrom(65535)
            return True
        except TimeoutError:
            return False

    wait_file("host.ready")
    offer1 = PairingOffer.from_uri(wait_file("offer1.txt"))
    host_addr = offer1.address.rsplit(":", 1)
    host = (host_addr[0], int(host_addr[1]))
    # (a) The first offer was used by the device; even knowing its secret doesn't help.
    sock.sendto(b"P" + make_request(me, offer1, "Mallory", sealer), host)
    out(event="used_offer", paired=answered())
    # (b) Five wrong guesses lock the second offer; then even the right secret fails.
    offer2 = PairingOffer.from_uri(wait_file("offer2.txt"))
    for _ in range(5):
        wrong = PairingOffer(
            offer2.host, offer2.name, offer2.address, bytes(16), offer2.expires, offer2.app
        )
        sock.sendto(b"P" + make_request(me, wrong, "Mallory", sealer), host)
        time.sleep(0.05)
    sock.sendto(b"P" + make_request(me, offer2, "Mallory", sealer), host)
    out(event="locked_offer", paired=answered())
    # (c) A message signed with the attacker's own key.
    sock.sendto(b"M" + sealer.seal(offer1.host, {"msg": "unlock"}), host)
    # (d) The same, claiming to be the device.
    env = json.loads(sealer.seal(offer1.host, {"msg": "unlock"}))
    env["from"] = wait_file("device.id")
    sock.sendto(b"M" + json.dumps(env).encode(), host)
    # (e) TCP: a frame claiming 50 MB, and one that is garbage.
    for frame in (struct.pack(">I", 50_000_000), struct.pack(">I", 5) + b"Mjunk"):
        with socket.create_connection(host, timeout=2) as c:
            c.sendall(frame)
    out(event="attacks_sent", count=4)
    (shared / "attack.done").write_text("1")

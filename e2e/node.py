"""One simulated device. Runs inside its own venv with lanpair installed from a package."""

import json
import os
import socket
import sys
import time
from pathlib import Path

import lanpair
from lanpair import (
    EnvelopeError,
    JsonFileSeqStore,
    Opener,
    PublicIdentity,
    Sealer,
    load_or_create_identity,
)
from lanpair.discovery import Announcer, browse, find

role, name, bridge_port, shared = sys.argv[1], sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
APP = "lanpair-sim"


def out(**kw):
    print(json.dumps({"node": name, **kw}), flush=True)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
bridge = ("127.0.0.1", bridge_port)
sock.sendto(f"HELLO {name}{' tap' if role == 'attacker' else ''}\n".encode(), bridge)
sock.recvfrom(100)


def send(to, payload):
    sock.sendto(f"TO {to}\n".encode() + payload, bridge)


def wait_file(p, timeout=30):
    end = time.time() + timeout
    while not p.exists():
        if time.time() > end:
            raise SystemExit(f"timeout waiting for {p}")
        time.sleep(0.1)
    return p.read_bytes()


out(event="start", version=lanpair.__version__, python=sys.version.split()[0], prefix=sys.prefix)
me = load_or_create_identity(name)
(shared / f"{name}.pub").write_bytes(me.public.to_bytes())
out(event="identity", device_id=me.public.device_id)

if role == "room":
    opener = Opener(me, store=JsonFileSeqStore(Path.home() / "seqs.json"))
    desk = PublicIdentity.from_bytes(wait_file(shared / "desk.pub"))  # pairing (out of band)
    opener.add_peer(desk)
    port = sock.getsockname()[1]
    with Announcer(me.public, f"Sim {name}", port, addresses=["127.0.0.1"], app=APP):
        out(event="announced", port=port)
        (shared / f"{name}.ready").write_text("1")
        sock.settimeout(1.0)
        idle = 0
        while idle < int(os.environ.get("IDLE", "8")):
            try:
                frame, _ = sock.recvfrom(65535)
            except TimeoutError:
                idle += 1
                continue
            idle = 0
            head, _, payload = frame.partition(b"\n")
            if payload == b"STOP":
                break
            try:
                peer, body = opener.open(payload)
                out(event="accepted", sender=peer.device_id, body=body, via=head.decode())
            except EnvelopeError as e:
                out(event="rejected", reason=str(e), via=head.decode())
    out(event="stopped")

elif role == "desk":
    sealer = Sealer(me)
    rooms = sys.argv[5].split(",")
    for r in rooms:
        wait_file(shared / f"{r}.ready")
    seen = {d.device_id: d for d in browse(3, app=APP)}
    for r in rooms:
        pub = PublicIdentity.from_bytes(wait_file(shared / f"{r}.pub"))
        d = (
            find(pub.device_id, seconds=3, app=APP)
            if pub.device_id not in seen
            else seen[pub.device_id]
        )
        out(
            event="found",
            room=r,
            ok=d is not None,
            address=d.address if d else None,
            name=d.name if d else None,
        )
    target = sys.argv[6]
    pub = PublicIdentity.from_bytes((shared / f"{target}.pub").read_bytes())
    for i, body in enumerate(json.loads(sys.argv[7])):
        send(target, sealer.seal(pub, body))
        out(event="sent", to=target, n=i)
        time.sleep(0.2)
    (shared / "desk.done").write_text("1")

elif role == "attacker":
    # Sniff everything on the segment until the desk is done sending (plus a moment).
    sock.settimeout(0.3)
    captured, done_at = [], None
    while done_at is None or time.time() < done_at + 1:
        if done_at is None and (shared / "desk.done").exists():
            done_at = time.time()
        try:
            frame, _ = sock.recvfrom(65535)
        except TimeoutError:
            continue
        head, _, payload = frame.partition(b"\n")
        if payload != b"STOP":
            captured.append((head.decode(), payload))
    plan = os.environ.get("PLAN", "all")
    saved = shared / "captured-phase1.json"  # what was recorded before the restart
    if plan == "all":
        saved.write_text(json.dumps([p.decode() for _, p in captured]))
    frames = [p.encode() for p in json.loads(saved.read_text())]
    secret = os.environ["SECRET"].encode()
    out(event="captured", count=len(captured), secret_visible=any(secret in p for _, p in captured))
    if plan == "replay":
        for f in frames:
            send("room1", f)
        out(event="attack", kind="replay-all")
    else:
        send("room1", frames[0])
        out(event="attack", kind="replay")
        m = json.loads(frames[1])
        ct = bytearray(m["ct"].encode())
        ct[5] = ord("A") if ct[5] != ord("A") else ord("B")
        m["ct"] = ct.decode()
        send("room1", json.dumps(m).encode())
        out(event="attack", kind="tamper-ciphertext")
        m = json.loads(frames[1])
        m["seq"] += 1
        send("room1", json.dumps(m).encode())
        out(event="attack", kind="tamper-seq")
        send("room2", frames[2])
        out(event="attack", kind="redirect-to-room2")
        room1 = PublicIdentity.from_bytes((shared / "room1.pub").read_bytes())
        send("room1", Sealer(me).seal(room1, {"cmd": "unlock"}))
        out(event="attack", kind="forge-own-key")
        m = json.loads(Sealer(me).seal(room1, {"cmd": "unlock"}))
        m["from"] = json.loads(frames[0])["from"]
        send("room1", json.dumps(m).encode())
        out(event="attack", kind="forge-impersonate-desk")
        for g in [b"", b"{}", b"\xff\xfe", b'{"v":2}', b"[" * 8000]:
            send("room1", g)
        out(event="attack", kind="garbage")
    time.sleep(1)

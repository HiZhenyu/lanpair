"""Orchestrates the simulated LAN: 4 isolated venvs + a bridge hub, two phases, checks."""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
# What to pip install: "lanpair[keyring,discovery]==1.0.0", or "lanpair[...] @ file:///x.whl"
SPEC = sys.argv[1]
WORK = HERE / "work"
NODES = ["desk", "room1", "room2", "attacker"]
SECRET = "door-code-4711"
BRIDGE = 47999
fails = []


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        fails.append(what)


def setup():
    shutil.rmtree(WORK, ignore_errors=True)
    for n in NODES:
        home = WORK / n
        home.mkdir(parents=True)
        subprocess.run([sys.executable, "-m", "venv", str(home / "venv")], check=True)
        subprocess.run(
            [
                str(home / "venv/bin/pip"),
                "install",
                "-q",
                "--no-cache-dir",
                "--disable-pip-version-check",
                SPEC,
                "keyrings.alt",
            ],
            check=True,
        )


def env(n, **extra):
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(WORK / n),
        "PYTHON_KEYRING_BACKEND": "keyrings.alt.file.PlaintextKeyring",
        "SECRET": SECRET,
        **extra,
    }


def start(role, n, *args, **extra):
    py = str(WORK / n / "venv/bin/python")
    return subprocess.Popen(
        [py, "-I", str(HERE / "node.py"), role, n, str(BRIDGE), str(WORK / "shared"), *args],
        env=env(n, **extra),
        cwd=WORK / n,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def collect(p, timeout=60):
    out, err = p.communicate(timeout=timeout)
    if p.returncode:
        print(f"--- process exited {p.returncode}:\n{err}")
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")], p.returncode


def phase(n_msgs, plan):
    shared = WORK / "shared"
    for f in [*shared.glob("*.ready"), *shared.glob("desk.done")]:
        f.unlink()
    rooms = {r: start("room", r) for r in ["room1", "room2"]}
    att = start("attacker", "attacker", LISTEN="7", PLAN=plan)
    time.sleep(0.5)
    bodies = [{"cmd": "close", "n": i, "note": SECRET} for i in range(n_msgs)]
    desk = start("desk", "desk", "room1,room2", "room1", json.dumps(bodies))
    d, rc_d = collect(desk)
    a, rc_a = collect(att)
    r1, rc1 = collect(rooms["room1"])
    r2, rc2 = collect(rooms["room2"])
    check(rc_d == rc_a == rc1 == rc2 == 0, f"[{plan}] every node exited cleanly")
    return d, a, r1, r2, bodies


shared = WORK / "shared"
if "--no-setup" not in sys.argv:
    setup()
shared.mkdir(exist_ok=True)
bridge = subprocess.Popen([sys.executable, str(HERE / "bridge.py"), str(BRIDGE)])
time.sleep(0.3)
try:
    # ---- phase 1: discovery, delivery, attacks
    d, a, r1, r2, bodies = phase(3, "all")
    starts = [e for e in d + a + r1 + r2 if e["event"] == "start"]
    check(len({e["prefix"] for e in starts}) == 4, "4 separate virtual environments")
    print("     versions:", {e["node"]: e["version"] for e in starts})
    ids1 = {e["node"]: e["device_id"] for e in d + a + r1 + r2 if e["event"] == "identity"}
    found = {e["room"]: e for e in d if e["event"] == "found"}
    ports = {e["node"]: e["port"] for e in r1 + r2 if e["event"] == "announced"}
    for r in ["room1", "room2"]:
        check(
            found[r]["ok"] and found[r]["address"] == f"127.0.0.1:{ports[r]}",
            f"mDNS: desk found {r} at its address",
        )
        check(found[r]["name"] == f"Sim {r}", f"mDNS: {r} name came through")
    acc = [e for e in r1 if e["event"] == "accepted"]
    check(
        [e["body"] for e in acc] == bodies,
        "room1 received exactly the 3 real messages, in order, intact",
    )
    check(all(e["sender"] == ids1["desk"] for e in acc), "room1 attributes them to the desk")
    cap = next(e for e in a if e["event"] == "captured")
    check(cap["count"] >= 3, "attacker captured the traffic on the bridge")
    check(not cap["secret_visible"], "attacker cannot read the message contents")
    rej = [e["reason"] for e in r1 if e["event"] == "rejected"]
    print("     room1 rejections:", rej)
    expect = {"replayed message": 1, "bad signature": 3, "unknown sender": 1}
    for reason, k in expect.items():
        check(rej.count(reason) == k, f"room1 rejected {k}x '{reason}'")
    check(
        len(rej) == 10
        and len([r for r in rej if r in ("malformed envelope", "unsupported envelope")]) == 5,
        "room1 rejected all 5 garbage frames without crashing",
    )
    r2rej = [e["reason"] for e in r2 if e["event"] == "rejected"]
    check(
        r2rej == ["not addressed to this device"]
        and not [e for e in r2 if e["event"] == "accepted"],
        "room2 refused the message redirected from room1",
    )

    # ---- library probe: hostile input that can't fit in one UDP packet
    probe = subprocess.run(
        [
            str(WORK / "room1/venv/bin/python"),
            "-I",
            "-c",
            """
from lanpair import EnvelopeError, Identity, Opener
o = Opener(Identity.generate())
for raw in (b'[' * 200000, b'{"a":' * 200000, b'x' * (2 << 20)):
    try:
        o.open(raw); print('ACCEPTED')
    except EnvelopeError as e:
        print('rejected')
    except BaseException as e:
        print('CRASH', type(e).__name__)
""",
        ],
        capture_output=True,
        text=True,
        env=env("room1"),
    )
    results = probe.stdout.split()
    print("     deep/huge input:", results)
    check(results == ["rejected"] * 3, "deeply nested and huge envelopes are rejected, not a crash")

    # ---- phase 2: restart everyone; identities from the key store; replay after restart
    d, a, r1, r2, bodies = phase(1, "replay")
    ids2 = {e["node"]: e["device_id"] for e in d + a + r1 + r2 if e["event"] == "identity"}
    check(ids1 == ids2, "every device has the same identity after a restart (OS key store)")
    rej = [e["reason"] for e in r1 if e["event"] == "rejected"]
    acc = [e for e in r1 if e["event"] == "accepted"]
    check(
        len(rej) >= 3 and set(rej) == {"replayed message"},
        f"after restart, all {len(rej)} replays rejected",
    )
    check([e["body"] for e in acc] == bodies, "after restart, the new message is accepted")
finally:
    import socket

    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"QUIT\n", ("127.0.0.1", BRIDGE))
    bridge.wait(5)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)

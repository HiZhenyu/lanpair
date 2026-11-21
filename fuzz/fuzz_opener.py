"""Coverage-guided fuzzing of Opener.open with Atheris.

Anything other than EnvelopeError (a crash, RecursionError, KeyError, ...) is a bug.
Run: python fuzz/fuzz_opener.py -max_total_time=60
"""

import sys

import atheris

with atheris.instrument_imports():
    from lanpair import EnvelopeError, Identity, Opener, Sealer

DESK, ROOM = Identity.from_seed(bytes(32)), Identity.from_seed(bytes([1]) * 32)
OPENER = Opener(ROOM, max_skew=1e12, clock=lambda: 2e12)
OPENER._started = -1e12  # no start-up window: let fuzzed envelopes reach every check
OPENER.add_peer(DESK.public)
SEED = Sealer(DESK, clock=lambda: 2e12).seal(ROOM.public, {"cmd": "close", "n": [1, 2.5, None]})


def test_one_input(data: bytes) -> None:
    try:
        OPENER.open(data)
    except EnvelopeError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

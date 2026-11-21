"""Render docs/assets/demo.gif: two terminal panes replaying a run of README's host.py and
device.py. The output lines are the ones those scripts print; the QR code is made from a
throwaway identity and an example address, so no real address or secret is published.

    pip install pillow "lanpair[qr]"
    python docs/assets/make_demo.py docs/assets/demo.gif

Needs the Menlo font (macOS).
"""

import sys

from PIL import Image, ImageDraw, ImageFont

from lanpair import Identity, PairingOffer

OUT = sys.argv[1]
W, H = 960, 380
PANE_W, GAP, TOP = 462, 12, 12
BG = (13, 17, 23)
PANE = (22, 27, 34)
BAR = (33, 38, 45)
FG = (230, 237, 243)
DIM = (139, 148, 158)
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)
YELLOW = (210, 153, 34)
FONT = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 14)
BOLD = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 14, index=1)
BIG = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 22, index=1)
LINE = 20

offer = PairingOffer.create(Identity.generate().public, "Front desk", "192.168.1.20:50505")
uri = offer.to_uri()
matrix = offer.qr().matrix


def qr_image(scale=3):
    n = len(matrix)
    img = Image.new("RGB", ((n + 8) * scale, (n + 8) * scale), (255, 255, 255))
    d = ImageDraw.Draw(img)
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            if cell:
                d.rectangle(
                    [(x + 4) * scale, (y + 4) * scale, (x + 5) * scale - 1, (y + 5) * scale - 1],
                    fill=(0, 0, 0),
                )
    return img


QR = qr_image()


def pane(draw, img, x, title, lines, qr=False):
    """lines: list of (text, colour) or ("<QR>", None)."""
    draw.rounded_rectangle([x, TOP, x + PANE_W, H - 12], 10, fill=PANE)
    draw.rounded_rectangle([x, TOP, x + PANE_W, TOP + 30], 10, fill=BAR)
    draw.rectangle([x, TOP + 20, x + PANE_W, TOP + 30], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([x + 12 + i * 18, TOP + 10, x + 24 + i * 18, TOP + 22], fill=c)
    draw.text((x + PANE_W / 2, TOP + 15), title, font=FONT, fill=DIM, anchor="mm")
    y = TOP + 44
    for text, colour in lines:
        if text == "<QR>":
            img.paste(QR, (int(x + 16), y))
            y += QR.height + 8
            continue
        draw.text((x + 16, y), text, font=FONT, fill=colour)
        y += LINE


def frame(host, dev, banner=None, card=False):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    pane(d, img, GAP, "Front desk — host.py", host)
    pane(d, img, GAP * 2 + PANE_W, "Room 3 — device.py", dev)
    if banner:
        d.rounded_rectangle([W / 2 - 230, H - 62, W / 2 + 230, H - 26], 8, fill=(31, 111, 235))
        d.text((W / 2, H - 44), banner, font=BOLD, fill=(255, 255, 255), anchor="mm")
    if card:
        overlay = Image.new("RGB", (W, H), BG)
        img = Image.blend(img, overlay, 0.82)
        d = ImageDraw.Draw(img)
        d.text((W / 2, H / 2 - 50), "lanpair", font=BIG, fill=FG, anchor="mm")
        d.text(
            (W / 2, H / 2 - 12),
            "pair once · encrypted · signed · replay-proof",
            font=FONT,
            fill=DIM,
            anchor="mm",
        )
        d.text(
            (W / 2, H / 2 + 30), 'pip install "lanpair[all]"', font=BOLD, fill=GREEN, anchor="mm"
        )
    return img


frames, durations = [], []


def add(img, ms):
    frames.append(img)
    durations.append(ms)


def typing(host, dev, side, cmd, prefix="$ "):
    """Frames typing *cmd* into one pane; returns the final line list for that pane."""
    for i in range(0, len(cmd) + 1, 2):
        line = (prefix + cmd[:i] + "▌", FG)
        if side == "host":
            add(frame(host + [line], dev), 45)
        else:
            add(frame(host, dev + [line]), 45)
    return [(prefix + cmd, FG)]


# --- first run: pair, then talk --------------------------------------------------------
host, dev = [], []
add(frame(host, dev, banner="First run: pair with a QR code"), 1400)
host = typing(host, dev, "host", "python host.py")
host += [("<QR>", None)]
add(frame(host, dev), 1600)
dev = typing(host, dev, "dev", "python device.py")
short = uri[:44] + "…"
dev += [("Scanned code:", FG), ("  " + short, BLUE)]
add(frame(host, dev), 1300)
host = host[:1] + [("<QR>", None), ("Room 3 {'type': 'checkout'}", GREEN)]
add(frame(host, dev), 1000)
dev += [("{'type': 'ok'}", GREEN)]
add(frame(host, dev), 1800)

# --- later: restart, no pairing ---------------------------------------------------------
host, dev = [], []
add(frame(host, dev, banner="After a restart: no pairing needed"), 1400)
host = typing(host, dev, "host", "python host.py")
dev = typing(host, dev, "dev", "python device.py")
host += [("Room 3 {'type': 'checkout'}", GREEN)]
add(frame(host, dev), 900)
dev += [("{'type': 'ok'}", GREEN)]
add(frame(host, dev), 1800)
add(frame(host, dev, card=True), 2800)

frames[0].save(
    OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True
)
print(len(frames), "frames,", sum(durations) / 1000, "s")

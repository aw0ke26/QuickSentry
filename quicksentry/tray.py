"""System tray icon (optional: needs pystray + Pillow; the app works without it)."""

try:
    import pystray
    from PIL import Image, ImageDraw
    AVAILABLE = True
except Exception:          # pragma: no cover - missing optional deps
    AVAILABLE = False

COLORS = {"ok": (40, 167, 69), "warn": (230, 160, 0), "alert": (220, 53, 69),
          "unknown": (120, 120, 120)}


def make_image(level="unknown", size=64):
    if not AVAILABLE:
        return None
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = COLORS.get(level, COLORS["unknown"])
    # simple shield shape
    w = size
    d.polygon([(w * .5, w * .04), (w * .92, w * .2), (w * .86, w * .62), (w * .5, w * .96),
               (w * .14, w * .62), (w * .08, w * .2)], fill=c + (255,))
    d.polygon([(w * .5, w * .16), (w * .8, w * .28), (w * .75, w * .58), (w * .5, w * .84),
               (w * .25, w * .58), (w * .2, w * .28)], fill=(255, 255, 255, 70))
    return img


class Tray:
    def __init__(self, on_show, on_toggle, on_exit):
        self.icon = None
        self.level = None
        if not AVAILABLE:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Open QuickSentry", lambda *_: on_show(), default=True),
            pystray.MenuItem("Start / stop monitoring", lambda *_: on_toggle()),
            pystray.MenuItem("Exit", lambda *_: on_exit()))
        self.icon = pystray.Icon("QuickSentry", make_image(), "QuickSentry", menu)

    @property
    def ok(self):
        return self.icon is not None

    def start(self):
        if self.icon:
            try:
                self.icon.run_detached()
            except Exception:
                self.icon = None

    def set_status(self, level, tooltip):
        if not self.icon:
            return
        try:
            if level != self.level:
                self.icon.icon = make_image(level)
                self.level = level
            self.icon.title = tooltip[:120]
        except Exception:
            pass

    def notify(self, title, msg):
        if self.icon:
            try:
                self.icon.notify(msg[:250], title[:60])
            except Exception:
                pass

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass

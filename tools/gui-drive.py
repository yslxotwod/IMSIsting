"""Drive the IMSIsting GUI on a throwaway display, and screenshot it.

The conventions require a UI change to be *seen* before it is called done, and
this is how. There is no window manager under Xvfb, so nothing hands the app
the keyboard: focus() does it, and every ctypes call needs explicit argtypes or
a 64-bit KeySym is passed as a 32-bit C int and every keycode resolves wrong.

    nohup Xvfb :99 -screen 0 1600x1000x24 &
    nohup dbus-run-session -- env DISPLAY=:99 GDK_BACKEND=x11 \
        IMSISTING_NO_SPLASH=1 ./native/builddir/imsisting-gui --module 21_lte_cve &
    sleep 14
    python3 -c "import sys; sys.path.insert(0,'tools'); \
                from importlib import import_module; \
                ui = import_module('gui-drive'); ui.focus(); ui.click(818,41); print(ui.shot('x'))"

--module <id> is the way in: typing does not reach the app under Xvfb, so the
search box is unusable, but clicks and scrolling work normally.
"""
import ctypes
import subprocess
import time

DISPLAY = ":99"

x11 = ctypes.CDLL("libX11.so.6")
xtst = ctypes.CDLL("libXtst.so.6")

x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
x11.XDefaultRootWindow.restype = ctypes.c_ulong
x11.XFlush.argtypes = [ctypes.c_void_p]
x11.XWarpPointer.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_int, ctypes.c_int, ctypes.c_uint,
                             ctypes.c_uint, ctypes.c_int, ctypes.c_int]
x11.XSetInputFocus.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                               ctypes.c_int, ctypes.c_ulong]
x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
x11.XStringToKeysym.restype = ctypes.c_ulong
x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
x11.XKeysymToKeycode.restype = ctypes.c_uint
xtst.XTestFakeButtonEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                      ctypes.c_int, ctypes.c_ulong]
xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                   ctypes.c_int, ctypes.c_ulong]

d = x11.XOpenDisplay(DISPLAY.encode())
if not d:
    raise SystemExit("no display " + DISPLAY)
root = x11.XDefaultRootWindow(ctypes.c_void_p(d))


def _flush():
    x11.XFlush(ctypes.c_void_p(d))


def windows():
    out = subprocess.run(["xwininfo", "-root", "-children"],
                         capture_output=True, text=True,
                         env={"DISPLAY": DISPLAY, "PATH": "/usr/bin:/bin"}).stdout
    res = []
    for line in out.splitlines():
        if "\":" in line and "(" in line:
            try:
                wid = line.strip().split()[0]
                name = line.split('"')[1]
                geo = [t for t in line.split() if "x" in t and "+" in t][0]
                wh, xy = geo.split("+")[0], geo
                w, h = wh.split("x")
                res.append({"id": wid, "name": name, "w": int(w), "h": int(h)})
            except Exception:
                pass
    return res


def focus():
    """There is no window manager on :99, so nothing ever gives the app the
       keyboard. Without this the clicks land and the keys go nowhere."""
    for w in windows():
        if w["w"] > 400 and w["h"] > 400:
            x11.XSetInputFocus(ctypes.c_void_p(d),
                               ctypes.c_ulong(int(w["id"], 16)), 2, 0)
            _flush()
            time.sleep(0.3)
            return w
    return None


def click(x, y, settle=0.6):
    x11.XWarpPointer(ctypes.c_void_p(d), 0, ctypes.c_ulong(root),
                     0, 0, 0, 0, int(x), int(y))
    _flush()
    time.sleep(0.35)
    xtst.XTestFakeButtonEvent(ctypes.c_void_p(d), 1, 1, 0)
    time.sleep(0.06)
    xtst.XTestFakeButtonEvent(ctypes.c_void_p(d), 1, 0, 0)
    _flush()
    time.sleep(settle)


def scroll(x, y, down=True, notches=6):
    button = 5 if down else 4
    x11.XWarpPointer(ctypes.c_void_p(d), 0, ctypes.c_ulong(root),
                     0, 0, 0, 0, int(x), int(y))
    _flush()
    time.sleep(0.2)
    for _ in range(notches):
        xtst.XTestFakeButtonEvent(ctypes.c_void_p(d), button, 1, 0)
        time.sleep(0.04)
        xtst.XTestFakeButtonEvent(ctypes.c_void_p(d), button, 0, 0)
        _flush()
        time.sleep(0.09)
    time.sleep(0.6)


def shot(name, crop="1180x760+0+0"):
    tmp = "/tmp/_shot.xwd"
    path = "/tmp/%s.png" % name
    subprocess.run(["xwd", "-root", "-silent"], stdout=open(tmp, "wb"),
                   env={"DISPLAY": DISPLAY, "PATH": "/usr/bin:/bin"})
    subprocess.run(["convert", tmp, "-crop", crop, "+repage", path])
    return path


def type_text(text):
    shift = x11.XKeysymToKeycode(ctypes.c_void_p(d),
                                 x11.XStringToKeysym(b"Shift_L"))
    for ch in text:
        name, sh = ch, False
        if ch == " ":
            name = "space"
        elif ch == "_":
            name, sh = "minus", True
        elif ch == "-":
            name = "minus"
        elif ch.isupper():
            name, sh = ch.lower(), True
        ks = x11.XStringToKeysym(name.encode())
        kc = x11.XKeysymToKeycode(ctypes.c_void_p(d), ks)
        if kc == 0:
            raise ValueError("no keycode for %r" % ch)
        if sh:
            xtst.XTestFakeKeyEvent(ctypes.c_void_p(d), shift, 1, 0)
        xtst.XTestFakeKeyEvent(ctypes.c_void_p(d), kc, 1, 0)
        xtst.XTestFakeKeyEvent(ctypes.c_void_p(d), kc, 0, 0)
        if sh:
            xtst.XTestFakeKeyEvent(ctypes.c_void_p(d), shift, 0, 0)
        _flush()
        time.sleep(0.05)


if __name__ == "__main__":
    print(windows())

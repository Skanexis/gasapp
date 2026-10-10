"""Мелкий помощник для проверки на эмуляторе: dump / tap / type.

  python ui.py dump                 — тексты и нажимаемые id экрана
  python ui.py tap id:<суффикс>     — нажать элемент по resource-id
  python ui.py tap text:<подстрока> — нажать элемент по тексту
  python ui.py type <текст>         — ввести текст в поле с фокусом
  python ui.py top                  — текущий экран и сбои
"""
import os
import re
import subprocess
import sys
import time

ADB = os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe")


def adb(*args):
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    return subprocess.run([ADB, *args], capture_output=True, env=env).stdout.decode("utf-8", "replace")


def nodes():
    for _ in range(3):
        adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
        xml = adb("shell", "cat", "/sdcard/ui.xml")
        if "<node" in xml:
            break
        time.sleep(1)
    out = []
    for m in re.finditer(r"<node ([^>]*?)/?>", xml):
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', m.group(1)))
        out.append(attrs)
    return out


def center(bounds):
    a, b, c, d = map(int, re.findall(r"\d+", bounds))
    return (a + c) // 2, (b + d) // 2


def main():
    cmd = sys.argv[1]
    if cmd == "dump":
        for n in nodes():
            rid = n.get("resource-id", "").split("/")[-1]
            text = n.get("text", "")
            flags = "".join(
                f for f, k in (("C", "clickable"), ("K", "checked"), ("E", "enabled"))
                if n.get(k) == "true"
            )
            if text or (rid and n.get("clickable") == "true"):
                print(f"{rid:32} [{flags:3}] {text[:110]}")
    elif cmd == "tap":
        kind, _, want = sys.argv[2].partition(":")
        for n in nodes():
            rid = n.get("resource-id", "").split("/")[-1]
            hit = (kind == "id" and rid == want) or (kind == "text" and want in n.get("text", ""))
            if hit:
                x, y = center(n["bounds"])
                adb("shell", "input", "tap", str(x), str(y))
                print("tap", rid or n.get("text", "")[:30], x, y)
                return
        print("НЕ НАЙДЕНО:", sys.argv[2])
        sys.exit(1)
    elif cmd == "type":
        adb("shell", "input", "text", sys.argv[2])
    elif cmd == "top":
        top = adb("shell", "dumpsys", "activity", "activities")
        m = re.search(r"topResumedActivity=.*?/([\w.]+)", top)
        print("экран:", m.group(1) if m else "?")
        crash = adb("logcat", "-d", "-s", "AndroidRuntime:E")
        lines = [l for l in crash.splitlines() if "AndroidRuntime" in l]
        print("сбоев в журнале:", len(lines))
        for l in lines[-12:]:
            print("  ", l[:190])


main()

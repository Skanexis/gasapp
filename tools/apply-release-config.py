#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Переносит tools/release.conf в настройки сборки Android и iOS.

    python3 tools/apply-release-config.py          # записать
    python3 tools/apply-release-config.py --check  # только проверить

Пишет:
* android/app/src/release/res/xml/network_security_config.xml — пины
  и expiration (адрес, onion и версию Android берёт из release.conf
  сама сборка, tools/release-android.sh);
* ios/Config/Base.xcconfig — адрес, сайт, onion, пины, expiration.

С --check ничего не меняет и выходит с кодом 1, если файлы расходятся
с release.conf (так его зовут скрипт выпуска и сборка TestFlight).
"""

from __future__ import annotations

import base64
import datetime
import io
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONF = ROOT / "tools" / "release.conf"
ANDROID = ROOT / "android/app/src/release/res/xml/network_security_config.xml"
IOS = ROOT / "ios/Config/Base.xcconfig"

PLACEHOLDERS = {"A" * 43 + "=", "B" * 43 + "="}


def load() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in io.open(CONF, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def validate(c: dict[str, str]) -> list[str]:
    problems = []
    for key in ("VERSION_NAME", "VERSION_CODE", "SERVER_URL", "DOCS_URL", "PIN_PRIMARY", "PIN_BACKUP", "PIN_EXPIRATION"):
        if not c.get(key):
            problems.append(f"в release.conf пусто: {key}")
    if problems:
        return problems
    for key in ("SERVER_URL", "DOCS_URL"):
        if not re.fullmatch(r"https://[a-z0-9.-]+", c[key]):
            problems.append(f"{key}: нужен https://имя без пути и слеша в конце")
    if not c["VERSION_CODE"].isdigit() or int(c["VERSION_CODE"]) < 1:
        problems.append("VERSION_CODE: целое число от 1")
    onion = c.get("SERVER_ONION", "")
    if onion and not re.fullmatch(r"[a-z2-7]{56}\.onion:\d{1,5}", onion):
        problems.append("SERVER_ONION: «56 знаков.onion:443»")
    for key in ("PIN_PRIMARY", "PIN_BACKUP"):
        pin = c[key]
        try:
            raw = base64.b64decode(pin, validate=True)
        except ValueError:
            raw = b""
        if len(raw) != 32 or pin in PLACEHOLDERS:
            problems.append(f"{key}: не пин SHA-256 в base64 (44 знака с «=» в конце)")
    if c["PIN_PRIMARY"] == c["PIN_BACKUP"]:
        problems.append("основной и запасной пины одинаковые — запасной должен быть от другого ключа")
    try:
        expiration = datetime.date.fromisoformat(c["PIN_EXPIRATION"])
        if expiration < datetime.date.today() + datetime.timedelta(days=180):
            problems.append("PIN_EXPIRATION ближе полугода — продлите (docs/ops/cert-pin-rotation.md)")
    except ValueError:
        problems.append("PIN_EXPIRATION: дата ГГГГ-ММ-ДД")
    return problems


def render_android(text: str, c: dict[str, str]) -> str:
    block = re.search(r'(<pin-set expiration=")[^"]*(">)(.*?)(\s*</pin-set>)', text, re.S)
    if not block:
        raise SystemExit(f"в {ANDROID} нет <pin-set>")
    indent = re.search(r"\n(\s*)<pin ", block.group(3)).group(1)
    pins = "".join(f'\n{indent}<pin digest="SHA-256">{p}</pin>' for p in (c["PIN_PRIMARY"], c["PIN_BACKUP"]))
    new = block.group(1) + c["PIN_EXPIRATION"] + block.group(2) + pins + block.group(4)
    return text[: block.start()] + new + text[block.end():]


def xcconfig_value(value: str) -> str:
    # В xcconfig «//» — начало комментария: в адресе и в base64 пина
    # оно заменяется на «/$()/», иначе остаток строки отрезался бы.
    return value.replace("//", "/$()/")


def render_ios(text: str, c: dict[str, str]) -> str:
    settings = {
        "GASAPP_SERVER_URL": c["SERVER_URL"],
        "GASAPP_SERVER_ONION": c.get("SERVER_ONION", ""),
        "GASAPP_DOCS_URL": c["DOCS_URL"],
        "GASAPP_PINS": f'{c["PIN_PRIMARY"]},{c["PIN_BACKUP"]}',
        "GASAPP_PIN_EXPIRATION": c["PIN_EXPIRATION"],
        "MARKETING_VERSION": c["VERSION_NAME"],
    }
    for key, value in settings.items():
        line = f"{key} = {xcconfig_value(value)}".rstrip()
        pattern = re.compile(rf"^{key} =.*$", re.M)
        if pattern.search(text):
            text = pattern.sub(lambda _: line, text, count=1)
        else:
            text = text.replace('#include? "Local.xcconfig"', f'// Версия, которую видит человек (tools/release.conf).\n{line}\n\n#include? "Local.xcconfig"')
    return text


def main() -> int:
    # Консоль Windows (cp1252) не печатает кириллицу.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    check = "--check" in sys.argv
    c = load()
    problems = validate(c)
    if problems:
        print("release.conf:\n  • " + "\n  • ".join(problems), file=sys.stderr)
        return 1
    changed = []
    for path, render in ((ANDROID, render_android), (IOS, render_ios)):
        old = io.open(path, encoding="utf-8").read()
        new = render(old, c)
        if new != old:
            changed.append(str(path.relative_to(ROOT)))
            if not check:
                io.open(path, "w", encoding="utf-8", newline="\n").write(new)
    if check and changed:
        print("не совпадают с tools/release.conf: " + ", ".join(changed), file=sys.stderr)
        print("запустите: python3 tools/apply-release-config.py", file=sys.stderr)
        return 1
    print("записано: " + ", ".join(changed) if changed else "настройки сборки совпадают с release.conf")
    return 0


if __name__ == "__main__":
    sys.exit(main())

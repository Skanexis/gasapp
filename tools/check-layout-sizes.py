#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""У каждого элемента разметки есть ширина и высота — атрибутом или стилем.

Зачем
-----
Элемент без `layout_height` не раздувается: `InflateException: You must
supply a layout_height attribute`. Экран падает при открытии — и вместе
с ним всё приложение.

Так было с семью экранами: File Vault, создание, подтверждение и центр
ключа восстановления, восстановление из копии, настройки сети и экран
смены ключа. Нашлось только первым запуском на эмуляторе — открытие
File Vault роняло приложение.

Ни одна проверка этого не видела:
* Android Lint (`RequiredSize`) молчит, если у элемента есть `style`:
  он допускает, что размер придёт из стиля, и не проверяет, приходит ли;
* Robolectric-тесты эти экраны не раздували, а один аудитор, увидев
  то же исключение в Robolectric, принял его за особенность стенда.

Здесь стиль разбирается по-настоящему: цепочка родителей, явных
(`parent=`) и неявных (`GasAppText.Body` → `GasAppText`), и размер
засчитывается, только если его действительно задаёт кто-то в ней.
"""

import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

ROOT = pathlib.Path(__file__).resolve().parent.parent
RES = ROOT / "android/app/src/main/res"

# Защита от пустого разбора: ноль найденных элементов «прошёл» бы проверку.
MIN_ELEMENTS = 200

SIZES = ("android:layout_width", "android:layout_height")
SKIPPED_TAGS = {"include", "merge", "requestFocus", "tag", "fragment", "view"}


def load_styles() -> dict[str, tuple[str | None, set[str]]]:
    styles: dict[str, tuple[str | None, set[str]]] = {}

    for path in (RES / "values").glob("*.xml"):
        text = path.read_text(encoding="utf-8")

        for match in re.finditer(r'<style name="([^"]+)"([^>]*)>(.*?)</style>', text, re.S):
            name, head, body = match.groups()
            explicit = re.search(r'parent="(?:@style/)?([^"]*)"', head)
            parent = explicit.group(1) if explicit else (name.rsplit(".", 1)[0] if "." in name else None)
            styles[name] = (parent or None, set(re.findall(r'<item name="([^"]+)"', body)))

    return styles


def items_of(style: str, styles: dict) -> set[str]:
    found: set[str] = set()
    seen: set[str] = set()

    while style and style in styles and style not in seen:
        seen.add(style)
        parent, items = styles[style]
        found |= items
        style = parent

    return found


def main() -> int:
    styles = load_styles()
    checked = 0
    missing: list[str] = []

    for path in sorted((RES / "layout").glob("*.xml")):
        # Комментарии вырезаются с сохранением переводов строк: номер
        # строки в сообщении обязан совпадать с тем, что назовёт
        # InflateException на устройстве.
        text = re.sub(
            r"<!--.*?-->",
            lambda comment: "\n" * comment.group(0).count("\n"),
            path.read_text(encoding="utf-8"),
            flags=re.S,
        )

        for match in re.finditer(r"<([A-Za-z][\w.]*)(\s[^>]*?)?/?>", text, re.S):
            tag, attrs = match.group(1), match.group(2) or ""
            if tag in SKIPPED_TAGS:
                continue

            checked += 1
            have = {size for size in SIZES if f"{size}=" in attrs}

            style = re.search(r'style="@style/([^"]+)"', attrs)
            if style:
                have |= {size for size in SIZES if size in items_of(style.group(1), styles)}

            # Строка конца тега — её называет InflateException на устройстве.
            line = text.count("\n", 0, match.end()) + 1
            for size in SIZES:
                if size not in have:
                    missing.append(f"{path.name}:{line}: <{tag}> без {size}")

    print(f"проверено элементов разметки: {checked}")

    if checked < MIN_ELEMENTS:
        print(f"error: найдено меньше {MIN_ELEMENTS} — разбор сломан", file=sys.stderr)
        return 1

    for problem in missing:
        print(f"error: {problem} — экран упадёт при открытии", file=sys.stderr)

    if missing:
        return 1

    print("у всех элементов есть размер")
    return 0


if __name__ == "__main__":
    sys.exit(main())

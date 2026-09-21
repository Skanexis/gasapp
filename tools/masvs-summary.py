#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Считает сводку docs/masvs-checklist.md по самим строкам таблиц.

Сводная таблица в конце чек-листа — ровно то место, где документ
расходится с собой: строку переводят из 🟡 в ✅ и забывают про итог.
Здесь она пересчитывается из источника.

    python tools/masvs-summary.py           # напечатать сводку
    python tools/masvs-summary.py --check   # сверить с таблицей в документе

Второй режим возвращает ненулевой код, если числа разошлись.
"""

import io
import os
import re
import sys

# Вывод принудительно в UTF-8: консоль Windows по умолчанию cp1252,
# и печать самих значков статуса падала бы с UnicodeEncodeError —
# то есть инструмент проверки документа не запускался бы там, где
# документ и пишут.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DOC = "docs/masvs-checklist.md"

OK, PART, NO, WAIVED = "\u2705", "\U0001F7E1", "\u274c", "\u26d4"
MARKS = (OK, PART, NO, WAIVED)

ROW = re.compile(r"^[A-Z]+-[\d.]+$")


def collect(text):
    """Раскладывает строки требований по разделам."""
    counts, section = {}, None

    for line in text.split("\n"):
        heading = re.match(r"^## MASVS-([A-Z]+)", line)

        if heading:
            section = heading.group(1)
            counts[section] = dict.fromkeys(MARKS, 0)
            continue

        if line.startswith("## "):
            section = None

        if not section or not line.startswith("| "):
            continue

        cells = [cell.strip() for cell in line.strip("|").split("|")]

        if len(cells) >= 3 and ROW.match(cells[0]):
            if cells[2] not in MARKS:
                raise SystemExit(f"{cells[0]}: неизвестный статус {cells[2]!r}")

            counts[section][cells[2]] += 1

    return counts


def existing_names(root):
    """Имена всех файлов репозитория — один обход вместо многих."""
    names = set()

    for current, dirs, files in os.walk(root):
        dirs[:] = [
            d
            for d in dirs
            if d not in {"target", "build", ".git", ".gradle", "node_modules"}
        ]

        names.update(files)

    return names


def check_paths(text, root):
    """Каждый файл, на который ссылается чек-лист, существует.

    🔐 Обоснование в чек-листе — это ссылка на проверяемое место.
    Ссылка на файл, которого нет, превращает обоснование в слова:
    читающий не может убедиться, а пишущий не узнаёт, что переименовал
    или удалил то, на что ссылался.

    ⚠️ Проверяется только существование. Что файл содержит именно то,
    что обещано строкой чек-листа, проверка не знает, — и это сказано
    здесь прямо, а не подразумевается. Строка CODE-1 утверждала, что
    `ios/Package.swift` объявляет `.iOS(.v13)`, когда там уже стояло
    `.v17`: файл был на месте, а утверждение о нём устарело.

    Возвращает список ненайденных путей.
    """
    names = existing_names(root)
    missing = []

    for quoted in sorted(set(re.findall(r"`([^`\s]+)`", text))):
        # Схема URI, а не путь: `aegis://…`.
        if "://" in quoted:
            continue

        # Фрагмент маршрута HTTP, а не файл: `/v1/keys/…`, `/count`.
        # Пути к файлам в чек-листе всегда относительные.
        if quoted.startswith("/"):
            continue

        # Ссылка на тест внутри файла: `путь::модуль::имя_теста`.
        # Проверяется файл, имя теста — не наше дело.
        quoted = quoted.split("::", 1)[0]

        # Артефакт сборки: до сборки его нет, и это нормально.
        if quoted.startswith("build/") or "/build/" in quoted:
            continue

        is_path = "/" in quoted or re.search(
            r"\.(kt|rs|swift|xml|sh|py|toml|gradle|md|yml|pro)$", quoted
        )

        if not is_path:
            continue

        # Сокращение вида `android/app/.../SomeTest.kt` — указание
        # на файл, а не путь: ищем по имени.
        if os.path.exists(os.path.join(root, quoted)):
            continue

        if quoted.rsplit("/", 1)[-1] in names:
            continue

        missing.append(quoted)

    return missing


def main():
    text = io.open(DOC, encoding="utf-8").read()
    counts = collect(text)

    total = dict.fromkeys(MARKS, 0)
    lines = []

    for section, marks in counts.items():
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                section, marks[OK], marks[PART], marks[NO], marks[WAIVED]
            )
        )

        for mark in MARKS:
            total[mark] += marks[mark]

    lines.append(
        "| **\u0418\u0442\u043e\u0433\u043e** | **{}** | **{}** | **{}** | **{}** |".format(
            total[OK], total[PART], total[NO], total[WAIVED]
        )
    )

    rendered = "\n".join(lines)

    if "--check" not in sys.argv:
        print(rendered)
        return 0

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    absent = check_paths(text, root)

    if absent:
        print("\u0447\u0435\u043a-\u043b\u0438\u0441\u0442 \u0441\u0441\u044b\u043b\u0430\u0435\u0442\u0441\u044f \u043d\u0430 \u043d\u0435\u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u044e\u0449\u0435\u0435:")

        for path in absent:
            print(f"  {path}")

        return 1

    missing = [line for line in lines if line not in text]

    if missing:
        print("\u0441\u0432\u043e\u0434\u043a\u0430 \u0440\u0430\u0437\u043e\u0448\u043b\u0430\u0441\u044c \u0441 \u0442\u0430\u0431\u043b\u0438\u0446\u0430\u043c\u0438:")
        print("\n".join(missing))

        return 1

    print("\u0441\u0432\u043e\u0434\u043a\u0430 \u0441\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

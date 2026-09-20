#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Перевод не разошёлся с оригиналом.

Приложение говорит на двух языках, и расхождение между ними не видно
ни компилятору, ни сборке: недостающая строка просто молча берётся
из языка по умолчанию, а лишний `%1$s` роняет приложение
`IllegalFormatException` — но только у того, кто выбрал этот язык,
и только на том экране.

Проверяется три вещи:

1. набор ключей совпадает: ни одной строки, которая есть в одном
   языке и отсутствует в другом;
2. спецификаторы формата совпадают по составу — иначе `String.format`
   упадёт в рантайме на чужом языке;
3. каталоги не пусты и найдено сравнимое число строк — без этого
   проверка прошла бы на двух пустых списках (раздел 23.5).

Запуск: `python tools/check-strings-parity.py` из корня репозитория.
Код возврата 0 — расхождений нет.
"""

import io
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RES = os.path.join("android", "app", "src", "main", "res")

# Язык по умолчанию — первый; с ним сравниваются остальные.
DEFAULT = "values"
TRANSLATIONS = ["values-ru"]

# Ниже этого числа строк каталог считается ненайденным, а не пустым.
MIN_STRINGS = 100

# `%s`, `%d`, `%1$s`, `%.1f` и подобные. `%%` — экранированный процент,
# не спецификатор, поэтому исключается заранее.
FORMAT = re.compile(r"%(?:\d+\$)?[-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z]")


def read(catalog):
    """Возвращает (строки, plurals) каталога как словари имя → содержимое."""
    path = os.path.join(RES, catalog, "strings.xml")

    if not os.path.isfile(path):
        fail(f"нет файла {path}")

    text = io.open(path, encoding="utf-8").read()

    strings = dict(
        re.findall(r'<string name="([^"]+)"[^>]*>(.*?)</string>', text, re.S)
    )
    plurals = dict(
        re.findall(r'<plurals name="([^"]+)"[^>]*>(.*?)</plurals>', text, re.S)
    )

    return strings, plurals


def specifiers(value):
    """Состав спецификаторов формата, без учёта порядка."""
    return sorted(FORMAT.findall(value.replace("%%", "")))


errors = []


def fail(message):
    errors.append(message)


def main():
    base_strings, base_plurals = read(DEFAULT)

    # Защита от «зелёной отметки ни над чем»: сравнение двух пустых
    # наборов прошло бы любую проверку ниже.
    if len(base_strings) < MIN_STRINGS:
        fail(
            f"в {DEFAULT}/strings.xml найдено {len(base_strings)} строк "
            f"(ожидалось не меньше {MIN_STRINGS}) — разбор сломан?"
        )

    print(f"{DEFAULT}: {len(base_strings)} строк, {len(base_plurals)} plurals")

    for catalog in TRANSLATIONS:
        strings, plurals = read(catalog)

        print(f"{catalog}: {len(strings)} строк, {len(plurals)} plurals")

        for kind, base, other in (
            ("строка", base_strings, strings),
            ("plurals", base_plurals, plurals),
        ):
            for name in sorted(set(base) - set(other)):
                fail(f"{catalog}: {kind} «{name}» не переведена")

            for name in sorted(set(other) - set(base)):
                fail(f"{catalog}: {kind} «{name}» лишняя — в {DEFAULT} её нет")

        for name in sorted(set(base_strings) & set(strings)):
            want = specifiers(base_strings[name])
            got = specifiers(strings[name])

            if want != got:
                fail(
                    f"{catalog}: у «{name}» спецификаторы {got}, "
                    f"а в {DEFAULT} — {want}: String.format упадёт"
                )

        for name in sorted(set(base_plurals) & set(plurals)):
            want = specifiers(base_plurals[name])
            got = specifiers(plurals[name])

            # У plurals спецификаторы повторяются по одному на форму,
            # а форм в русском три, в английском две. Поэтому
            # сравнивается состав, а не количество.
            if set(want) != set(got):
                fail(
                    f"{catalog}: у plurals «{name}» спецификаторы "
                    f"{sorted(set(got))}, а в {DEFAULT} — {sorted(set(want))}"
                )

    if errors:
        print()
        for message in errors:
            print(f"  ✗ {message}")
        print(f"\nрасхождений: {len(errors)}")
        return 1

    print("\nрасхождений нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())

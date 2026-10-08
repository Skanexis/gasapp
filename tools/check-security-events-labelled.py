#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Каждое событие журнала безопасности, которое пишет ядро, имеет подпись.

Зачем
-----
Журнал безопасности писался, но прочитать его было негде: экрана
не было. Теперь он показывается в центре безопасности, и у каждого
типа события есть человеческая подпись (`core/SecurityEvents.kt`).

Событие без подписи экран не прячет — показывает сырой тип. Но
появиться незаметно оно не должно: новое событие безопасности
без понятного названия — это событие, которое человек не поймёт
ровно тогда, когда оно важно.

Проверяется в обе стороны:
* ядро пишет тип, которого нет среди подписей — ошибка;
* подпись есть, а ядро такого типа не пишет — ошибка: подпись
  к событию, которого не бывает, обещает то, чего не происходит.

⚠️ Тестовые модули не считаются: события, которые пишут только тесты
хранилища, продукт не порождает.
"""

import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
LABELS = ROOT / "android/app/src/main/kotlin/org/gasapp/app/core/SecurityEvents.kt"

# Защита от пустого сравнения: ноль найденных событий с обеих сторон
# «совпал» бы, и проверка была бы зелёной, ничего не проверив.
MIN_EVENTS = 5

CALL = re.compile(r"log_security_event\(")
LITERAL = re.compile(r'"([a-z][a-z0-9_]*)"')
SKIPPED_PARTS = {"target", "tests", "fuzz"}


def first_argument(text: str, start: int) -> str:
    """Первый аргумент вызова — до запятой верхнего уровня.

    Тип события бывает выбран условием (`if verified { "a" } else { "b" }`),
    поэтому берётся весь аргумент, а из него — все литералы.
    """
    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(text)):
        char = text[index]

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return text[start:index]
            depth -= 1
        elif char == "," and depth == 0:
            return text[start:index]

    return text[start:]


def logged_events() -> set[str]:
    found: set[str] = set()

    for path in CRATES.rglob("*.rs"):
        if SKIPPED_PARTS & set(path.parts):
            continue

        production = path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]

        for call in CALL.finditer(production):
            for literal in LITERAL.finditer(first_argument(production, call.end())):
                found.add(literal.group(1))

    return found


def labelled_events() -> set[str]:
    text = LABELS.read_text(encoding="utf-8")

    return set(re.findall(r'"([a-z][a-z0-9_]*)"\s+to\s+R\.string\.', text))


def main() -> int:
    logged = logged_events()
    labelled = labelled_events()

    print(f"ядро пишет: {len(logged)} типов событий")
    print(f"подписано:  {len(labelled)}")

    if len(logged) < MIN_EVENTS or len(labelled) < MIN_EVENTS:
        print(f"error: найдено меньше {MIN_EVENTS} — разбор сломан, сравнение пустое", file=sys.stderr)
        return 1

    missing = sorted(logged - labelled)
    stale = sorted(labelled - logged)

    for event in missing:
        print(f"error: событие «{event}» пишется, но подписи нет в SecurityEvents.kt", file=sys.stderr)
    for event in stale:
        print(f"error: подпись «{event}» есть, но ядро такого события не пишет", file=sys.stderr)

    if missing or stale:
        return 1

    print("расхождений нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())

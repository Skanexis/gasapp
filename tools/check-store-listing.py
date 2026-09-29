#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Проверяет тексты листинга (docs/store/listing.md) по лимитам магазинов.

Лимит берётся из заголовка поля: «### Краткое описание (≤ 80)».
Если в заголовке есть слово «байт», считаются байты UTF-8 (ключевые
слова App Store: кириллица — два байта на букву), иначе — символы.
Каждый блок ```text под заголовком проверяется отдельно (RU, EN).

Выход 1, если хоть одно поле длиннее лимита.
"""

import pathlib
import re
import sys

LISTING = pathlib.Path(__file__).resolve().parent.parent / "docs" / "store" / "listing.md"
HEADING = re.compile(r"^###\s+(?P<name>.+?)\s*\(≤\s*(?P<limit>\d+)(?P<rest>[^)]*)\)")


def main() -> int:
    # Консоль Windows по умолчанию не в UTF-8, а поля — кириллица.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    limit = None
    in_bytes = False
    field = ""
    block = None
    failed = False

    for line in LISTING.read_text(encoding="utf-8").splitlines():
        if block is None:
            heading = HEADING.match(line)
            if heading:
                field = heading["name"]
                limit = int(heading["limit"])
                in_bytes = "байт" in heading["rest"]
            elif line.startswith("#"):
                limit = None
            elif line.strip() == "```text" and limit is not None:
                block = []
            continue

        if line.strip() == "```":
            text = "\n".join(block)
            size = len(text.encode("utf-8")) if in_bytes else len(text)
            unit = "байт" if in_bytes else "симв."
            mark = "ok " if size <= limit else "ДЛИННО"
            print(f"{mark} {field}: {size}/{limit} {unit} — {text[:40]!r}")
            failed |= size > limit
            block = None
        else:
            block.append(line)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

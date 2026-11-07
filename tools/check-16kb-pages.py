#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Проверка APK на готовность к страницам памяти 16 КБ.

# Зачем

Google Play с ноября 2025 не принимает обновления приложений под
Android 15+, если их 64-битные нативные библиотеки не готовы
к устройствам со страницей 16 КБ. На таком устройстве библиотека
с выравниванием 4 КБ не загружается — приложение падает при первом
вызове ядра.

Нашлось не у нас: libgasapp.so собиралась правильно, а сторонняя JNA
5.14 для x86_64 — с выравниванием 4 КБ. Lint об этом лишь
предупреждал, и предупреждение терялось среди полусотни других.

# Что проверяется

Для каждой библиотеки lib/arm64-v8a/*.so и lib/x86_64/*.so в APK:

* выравнивание каждого сегмента PT_LOAD — не меньше 16 КБ;
* если библиотека лежит в APK без сжатия (так её грузит система прямо
  из архива), смещение её данных в архиве кратно 16 КБ.

32-битные ABI требованию не подлежат.

Запуск:  python tools/check-16kb-pages.py путь/к/app.apk [...]
"""

import struct
import sys
import zipfile

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

PAGE = 16 * 1024
ABIS_64 = ("arm64-v8a", "x86_64")
PT_LOAD = 1


def load_alignments(data: bytes) -> list[int]:
    """Выравнивания сегментов PT_LOAD 64-битного ELF."""
    if data[:4] != b"\x7fELF":
        raise ValueError("не ELF")
    if data[4] != 2:
        raise ValueError("не 64-битный ELF")

    endian = "<" if data[5] == 1 else ">"
    e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 0x36)

    aligns = []
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        p_type = struct.unpack_from(endian + "I", data, offset)[0]
        if p_type == PT_LOAD:
            aligns.append(struct.unpack_from(endian + "Q", data, offset + 0x30)[0])
    return aligns


def data_offset(apk: zipfile.ZipFile, info: zipfile.ZipInfo, raw) -> int:
    """Смещение данных записи: заголовок локального файла + имя + extra."""
    raw.seek(info.header_offset)
    header = raw.read(30)
    name_len, extra_len = struct.unpack_from("<HH", header, 26)
    return info.header_offset + 30 + name_len + extra_len


def check(path: str) -> list[str]:
    problems = []
    checked = 0
    only_32 = 0

    with open(path, "rb") as raw, zipfile.ZipFile(path) as apk:
        for info in apk.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
                continue
            if parts[1] not in ABIS_64:
                only_32 += 1
                continue

            checked += 1
            name = info.filename

            try:
                aligns = load_alignments(apk.read(info))
            except ValueError as error:
                problems.append(f"{name}: {error}")
                continue

            small = [a for a in aligns if a < PAGE]
            if small:
                problems.append(f"{name}: выравнивание PT_LOAD {', '.join(hex(a) for a in small)} < 0x4000")

            if info.compress_type == zipfile.ZIP_STORED:
                offset = data_offset(apk, info, raw)
                if offset % PAGE:
                    problems.append(f"{name}: смещение в APK {offset} не кратно 16 КБ (zipalign -P 16)")

    # APK одной 32-битной архитектуры (разбиение `splits` в build.gradle) —
    # законный случай: требование 16 КБ к нему не относится. Ошибка — только
    # APK без нативных библиотек вовсе: значит, проверка смотрит не туда.
    if checked == 0 and only_32:
        print(f"{path}: только 32-битные библиотеки ({only_32}) — требование 16 КБ не применяется")
        return problems

    if checked == 0:
        problems.append("нет ни одной нативной библиотеки — проверять нечего")

    print(f"{path}: 64-битных библиотек {checked}")
    return problems


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    failed = 0
    for path in sys.argv[1:]:
        for problem in check(path):
            print(f"  ✗ {problem}")
            failed += 1

    if failed:
        print(f"\nне готово к страницам 16 КБ: {failed}", file=sys.stderr)
        return 1

    print("все 64-битные библиотеки готовы к страницам 16 КБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())

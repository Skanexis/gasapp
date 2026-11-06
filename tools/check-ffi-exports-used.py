#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Каждая функция, выведенная через FFI, вызывается приложением.

Зачем
-----
Самый частый дефект этого проекта выглядит так: механизм написан,
покрыт тестами, выведен через FFI — и не вызывается ниоткуда.
Тесты зелёные, потому что проверяют механизм сам по себе; продукт
его не содержит.

Так было с удалением файла из хранилища (документ обещал «до удаления
пользователем»), с журналом безопасности (писался, читать было негде),
со сроком автоблокировки (читался, не записывался), с отметкой
о сверке safety number. Каждый раз — отдельная находка вручную.

Эта проверка находит их все сразу: для каждой функции и метода
с `#[uniffi::export]` ищется вызов в Kotlin приложения (без
сгенерированных привязок). Не найден — ошибка, если функция
не внесена в ALLOWED с причиной.

Список исключений проверяется тоже: исключение для функции, которую
уже вызывают или которой больше нет, — устаревшее и должно уйти.
Иначе список рос бы и прятал новые случаи за старыми причинами.
"""

import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

ROOT = pathlib.Path(__file__).resolve().parent.parent
FFI = ROOT / "crates/gasapp-ffi/src"
APP = ROOT / "android/app/src/main/kotlin/org"

# Защита от пустого сравнения: сломанный разбор нашёл бы ноль экспортов,
# и проверка была бы зелёной, не проверив ничего.
MIN_EXPORTS = 50

# Осознанно не вызываемые из приложения — каждая с причиной.
ALLOWED: dict[str, str] = {
    "check_protocol_version": (
        "Выведена ради платформенного теста отказа от понижения версии "
        "(ADR-021). Такого теста нет: отказ проверяется только в Rust."
    ),
    "identity_change_alert": (
        "Недостижима по устройству: сравнивает ключи по счёту, а счёт "
        "выводится из ключа. Ждёт решения о смене ключа собеседника "
        "(GASAPP_MASTER_PLAN.md, «Смена ключа собеседника»)."
    ),
    "inspect_backup": (
        "Предпросмотр копии до восстановления не сделан; восстановление "
        "работает без него и ничего о предпросмотре не обещает."
    ),
    "send_reaction": (
        "Реакции не хранятся и не показываются ни у отправителя, ни у "
        "получателя: ядро выбрасывает их при приёме. Пункт «Реакция» "
        "убран из меню сообщения, пока их некуда деть."
    ),
    "send_typing": (
        "Приложение не показывает индикатор набора: ядро выбрасывает его "
        "при приёме. Отправка без показа только сообщала серверу моменты "
        "набора, поэтому приложение его не шлёт."
    ),
    "maintain_storage": (
        "Плановый VACUUM. auto_vacuum = FULL уже возвращает освобождённые "
        "страницы, а secure_delete и контрольная точка WAL закрывают "
        "остатки удалённого; остаётся только дефрагментация."
    ),
}


def camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def exported() -> set[str]:
    names: set[str] = set()

    for path in FFI.glob("*.rs"):
        text = path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]

        for match in re.finditer(r"#\[uniffi::export\]\s*(?:#\[[^\]]*\]\s*)*pub fn (\w+)", text):
            names.add(match.group(1))

        for block in re.finditer(r"#\[uniffi::export\]\s*impl \w+ \{(.*?)\n\}", text, re.S):
            for match in re.finditer(r"\n    pub fn (\w+)", block.group(1)):
                names.add(match.group(1))

    return names


def app_source() -> str:
    # Все варианты Android (main и flavor'ы: пуши FCM живут в src/gms)
    # и приложение iOS — без сгенерированных привязок: их вызов функции
    # «использованием» не считается.
    kotlin = [
        path
        for path in (ROOT / "android/app/src").glob("*/kotlin/org/**/*.kt")
    ]
    swift = [
        path
        for path in (ROOT / "ios/GasApp").rglob("*.swift")
        if "Generated" not in path.parts
    ]
    return "\n".join(path.read_text(encoding="utf-8") for path in kotlin + swift)


def main() -> int:
    names = exported()
    source = app_source()

    print(f"выведено через FFI: {len(names)}")

    if len(names) < MIN_EXPORTS:
        print(f"error: найдено меньше {MIN_EXPORTS} — разбор сломан", file=sys.stderr)
        return 1

    def used(name: str) -> bool:
        return re.search(r"\b" + re.escape(camel(name)) + r"\b", source) is not None

    unused = sorted(name for name in names if not used(name))
    failures = 0

    for name in unused:
        if name not in ALLOWED:
            print(f"error: «{name}» выведена через FFI, но приложение её не вызывает", file=sys.stderr)
            failures += 1

    for name in sorted(ALLOWED):
        if name not in names:
            print(f"error: исключение для «{name}», но такой функции больше нет", file=sys.stderr)
            failures += 1
        elif used(name):
            print(f"error: исключение для «{name}», но её уже вызывают — уберите из ALLOWED", file=sys.stderr)
            failures += 1

    print(f"не вызывается: {len(unused)}, из них в исключениях: {len(set(unused) & set(ALLOWED))}")

    if failures:
        return 1

    print("расхождений нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())

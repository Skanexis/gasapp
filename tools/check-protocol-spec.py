#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Спецификация протокола не разошлась с реализацией.

`docs/protocol/AEGIS-PROTOCOL-v1.md` — документ, по которому чужая
реализация должна заговорить с нашей, и по которому её будет читать
аудитор. Расхождение здесь дороже обычной опечатки в документации:
оно приводит к реализации, которая не совместима, — и обнаружится это
не на сборке, а на первом сообщении, которое не расшифровалось.

Сверяются те утверждения спецификации, которые можно сверить
механически: метки разделения доменов, числовые параметры и набор
примитивов. Всё это — константы, и расходятся они молча.

⚠️ Чего проверка не делает. Она не читает спецификацию на смысл:
описание шага ратчета может разойтись с кодом так, что ни одна
константа не изменится. Это остаётся работой человека, и раздел
«что осталось открытым» в плане говорит об этом прямо.

Запуск: `python tools/check-protocol-spec.py` из корня репозитория.
Код возврата 0 — расхождений нет.
"""

import io
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SPEC = os.path.join("docs", "protocol", "AEGIS-PROTOCOL-v1.md")
CRATES = "crates"

errors = []
checked = 0


def fail(message):
    errors.append(message)


def sources():
    """Все исходники Rust ядра одной строкой."""
    blob = []

    for root, _dirs, files in os.walk(CRATES):
        parts = root.split(os.sep)

        # Тесты не в счёт: `rfc_vectors.rs` держит прежнюю метку PQXDH
        # как вход HKDF, и сверка находила её там, пропуская
        # спецификацию, отставшую от кода.
        if "target" in parts or "tests" in parts:
            continue

        for name in files:
            if name.endswith(".rs"):
                path = os.path.join(root, name)
                blob.append(io.open(path, encoding="utf-8", errors="replace").read())

    return "\n".join(blob)


def check_labels(spec, code):
    """Метки разделения доменов из спецификации есть в коде.

    Метка — это то, что входит в KDF. Разойдись она на один символ,
    и две реализации выведут разные ключи из одних и тех же секретов:
    рукопожатие пройдёт, сообщение не расшифруется, а причину будут
    искать в сети.
    """
    global checked

    labels = sorted(set(re.findall(r'"(AEGIS_[A-Za-z0-9_]+)"', spec)))

    # 🔐 Без этой проверки сравнение шло бы по пустому списку — та же
    # ловушка, что трижды поймана в разделе 23.5 плана.
    if len(labels) < 4:
        fail(
            f"в спецификации найдено {len(labels)} меток домена "
            "(ожидалось не меньше 4) — разбор сломан?"
        )

        return

    print(f"меток разделения доменов в спецификации: {len(labels)}")

    for label in labels:
        checked += 1

        if label not in code:
            fail(f"метка «{label}» описана в спецификации, но в коде её нет")
        else:
            print(f"  ✅ {label}")


def check_numbers(spec, code):
    """Числовые параметры совпадают с константами кода.

    Каждая пара — (как named в спецификации, что искать в коде).
    Ищется именно значение: имя константы в коде может быть любым,
    а вот число обязано совпадать.
    """
    global checked

    # (описание, регулярное выражение по спецификации, что обязано
    #  найтись в коде с этим же значением)
    rules = [
        (
            "число итераций SHA-512 для отпечатка",
            r"SHA-512\^(\d+)",
            # Именно названная константа, а не «встречается ли такое
            # число где-нибудь». В миллионе символов исходников любое
            # четырёхзначное число найдётся, и проверка по \b...\b
            # проходила бы всегда — проверено мутацией.
            lambda value: re.search(rf"FINGERPRINT_ROUNDS[^=]*=\s*{value}\b", code)
            is not None,
        ),
        (
            "длина отпечатка в байтах",
            r"first_(\d+)_bytes\(SHA-512",
            lambda value: re.search(rf"FINGERPRINT_LEN[^=]*=\s*{value}\b", code)
            is not None,
        ),
        (
            "длина nonce AEAD в байтах",
            r"first_(\d+)_bytes\(HKDF-SHA-256\(salt=none, IKM=message_key\)",
            lambda value: re.search(rf"NONCE_LEN[^=]*=\s*{value}\b", code) is not None,
        ),
        (
            "длина тега GCM в байтах",
            r"AuthTag \((\d+) bytes\)",
            lambda value: re.search(rf"TAG_LEN[^=]*=\s*{value}\b", code) is not None,
        ),
        (
            "длина заголовка в байтах",
            r"Header \((\d+) bytes\)",
            lambda value: re.search(rf"HEADER_LEN[^=]*=\s*{value}\b", code) is not None,
        ),
    ]

    for name, pattern, present in rules:
        match = re.search(pattern, spec)

        if not match:
            fail(f"в спецификации не нашлось утверждение про {name} — она изменилась?")

            continue

        value = match.group(1)
        checked += 1

        if present(value):
            print(f"  ✅ {name}: {value}")
        else:
            fail(
                f"{name}: спецификация говорит {value}, "
                "а константы с таким значением в коде нет"
            )


def check_primitives(spec, code):
    """Названные примитивы действительно используются.

    Ловит ровно одно: примитив назван в спецификации, а в коде его
    нет (или наоборот — исчез из спецификации). Этого достаточно,
    чтобы заметить выпавший из реализации алгоритм.

    ⚠️ **Подмену уровня стойкости это не ловит.** Спецификация,
    заменившая ML-KEM-1024 на ML-KEM-512 в одном месте из трёх,
    проходит: имя всё ещё встречается в документе, а ML-KEM-768
    честно присутствует в коде — его использует SPQR. Проверено
    мутацией, и записано здесь, а не выдано за проверку, которой нет.

    То, где какой уровень применяется, закреплено меткой домена
    (`AEGIS_PQXDH_v1_X25519_MLKEM1024`): её сверяет [`check_labels`],
    и вот она к подмене чувствительна.
    """
    global checked

    primitives = {
        "ML-KEM-1024": r"MlKem1024|ml_kem_1024|MLKEM1024",
        "ML-KEM-768": r"MlKem768|ml_kem_768|MLKEM768",
        "AES-256-GCM": r"Aes256Gcm|aes256gcm",
        "HKDF-SHA-256": r"Hkdf::<Sha256>|hkdf.*Sha256|HkdfSha256",
        "HMAC-SHA-256": r"Hmac::<Sha256>|HmacSha256",
        "SHA-512": r"Sha512",
        "X25519": r"x25519|X25519",
        "XEdDSA": r"xeddsa",
    }

    for name, pattern in primitives.items():
        if name not in spec:
            fail(f"примитив {name} пропал из спецификации")

            continue

        checked += 1

        if re.search(pattern, code, re.IGNORECASE):
            print(f"  ✅ {name}")
        else:
            fail(f"спецификация называет {name}, но в коде его не видно")


def main():
    if not os.path.isfile(SPEC):
        print(f"нет файла {SPEC}")

        return 1

    spec = io.open(SPEC, encoding="utf-8").read()
    code = sources()

    if len(code) < 100_000:
        print(f"прочитано {len(code)} символов исходников — это подозрительно мало")

        return 1

    print(f"спецификация: {len(spec.splitlines())} строк")
    print(f"исходники ядра: {len(code)} символов\n")

    check_labels(spec, code)
    print("\nчисловые параметры:")
    check_numbers(spec, code)
    print("\nпримитивы:")
    check_primitives(spec, code)

    print(f"\nсверено утверждений: {checked}")

    if errors:
        print()
        for message in errors:
            print(f"  ✗ {message}")
        print(f"\nрасхождений: {len(errors)}")

        return 1

    print("расхождений нет")

    return 0


if __name__ == "__main__":
    sys.exit(main())

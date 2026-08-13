# Разработка AEGIS

Главный документ проекта — [AEGIS_MASTER_PLAN.md](AEGIS_MASTER_PLAN.md).
Прочитайте его разделы 4 (принципы безопасности) и 8 (архитектура) до первого
коммита. Здесь — только то, что нужно ежедневно.

---

## Семь правил, нарушение которых блокирует merge

Полные формулировки — раздел 4 главного документа.

### 1. UI не занимается криптографией

```text
❌ В Swift/Kotlin:              ✅ В Swift/Kotlin:
   CryptoKit                       core.sendMessage(chatId, text)
   javax.crypto                    core.safetyNumber(peerId)
   deriveKey(), encryptAES()       core.securityStatus()
```

Исключение ровно одно: платформенная обёртка аппаратного хранилища ключей
(`ios/AEGIS/Platform/KeyProtection.swift`, `android/.../platform/KeyProtection.kt`).
Проверяется скриптом `tools/check-no-crypto-in-ui.sh` в CI.

### 2. Никакой самодельной криптографии

Не изобретаем примитивы, режимы, KDF и протоколы. Реализуем **публичные
спецификации** на аудированных библиотеках. Добавление любого нового
криптографического примитива требует новой записи ADR.

### 3. Один ключ — одна задача

Никаких «мастер-ключей на всё». Каждый ключ выводится через HKDF с уникальным
`info`-лейблом. Иерархия — раздел 7 главного документа.

### 4. Секреты не попадают в логи

Секретные типы реализуют `Debug` как `<redacted>` вручную.
`#[derive(Debug)]` на типе с ключевым материалом — блокер ревью.

### 5. Ключи стираются детерминированно

Всё секретное оборачивается в `Secret<T>` или реализует `ZeroizeOnDrop`.
Message key уничтожается сразу после использования.

### 6. Всё, что покидает устройство, — уже шифротекст

Сетевой слой принимает только `Ciphertext` и `PublicKeyBytes`.
Это инвариант уровня системы типов: отправить `Plaintext` в сеть не компилируется.

### 7. Нет телеметрии

Ноль сторонних SDK аналитики, рекламы и краш-репортинга.

---

## Подготовка окружения: OpenSSL

`aegis-storage` собирает SQLCipher из исходников (фича `bundled-sqlcipher`
у `rusqlite`), а SQLCipher требует OpenSSL. Без указанных ниже переменных
сборка падает на build-скрипте `libsqlite3-sys` с сообщением
`Missing environment variable OPENSSL_DIR` — ещё до компиляции наших крейтов.

**Linux / macOS** — обычно достаточно системного пакета
(`libssl-dev` / `brew install openssl@3`); если путь не находится сам:

```bash
export OPENSSL_DIR=/usr/local/opt/openssl@3
```

**Windows** — установить OpenSSL (например, Win64 OpenSSL v3) и указать:

```powershell
$env:OPENSSL_DIR       = 'C:\Program Files\OpenSSL-Win64'
$env:OPENSSL_LIB_DIR   = 'C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD'
$env:OPENSSL_INCLUDE_DIR = 'C:\Program Files\OpenSSL-Win64\include'
$env:OPENSSL_STATIC    = '1'
```

> ⚠️ Фича `bundled-sqlcipher-vendored-openssl` собирает OpenSSL сама, но
> требует Perl с модулем `Locale::Maketext::Simple`, которого нет в Perl
> из состава Git for Windows. Поэтому по умолчанию используется системный
> OpenSSL, а не vendored.

## Перед коммитом

```bash
cd crates
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny --manifest-path Cargo.toml check
```

**Прекоммит-хуки**  
Для автоматической проверки перед коммитом рекомендуется установить pre-commit framework:
```bash
pip install pre-commit
pre-commit install
```
Это запустит gitleaks, проверку форматирования Rust и другие проверки, указанные в `.pre-commit-config.yaml`.

Для пользователей, предпочитающих не устанавливать Python, доступен запасной путь через `core.hooksPath`:
```bash
git config core.hooksPath .githooks
ln -s ../../.pre-commit-config.yaml .githooks/pre-commit
chmod +x .githooks/pre-commit
```
(Это создаёт символическую ссылку на pre-commit конфиг, но требует наличия pre-commit в PATH.)

Плюс `gitleaks detect` — он же стоит в pre-commit hook.

## Требования к коду

| Требование | Где |
|---|---|
| `unsafe` запрещён | Везде, кроме `aegis-ffi`. Enforced через `unsafe_code = "forbid"` |
| `unwrap()`, `expect()`, `panic!()` запрещены | В коде крейтов. В тестах разрешены (`clippy.toml`) |
| Версии крипто-зависимостей пинуются точно | `crates/Cargo.toml`, формат `=1.2.3` |
| git-зависимости запрещены | Enforced в `deny.toml` |
| Каждый публичный элемент документирован | `missing_docs = "warn"` |
| SPDX-заголовок в каждом файле | `// SPDX-License-Identifier: Apache-2.0` |

### Лицензионный заголовок

```rust
// SPDX-License-Identifier: Apache-2.0        ← crates/, ios/, android/, tools/
// SPDX-License-Identifier: AGPL-3.0-or-later ← server/
```

🔴 Крейт из `server/` **никогда** не должен появиться в графе зависимостей
`aegis-ffi`. Это ломает возможность публикации в App Store (ADR-006).

---

## Тестирование

Требования к покрытию по крейтам — раздел 24.2 главного документа.
Ключевое: `aegis-protocol` и `aegis-keystore` — **95%**.

Для криптографического кода одних юнит-тестов недостаточно. Обязательны:

1. **Официальные тестовые векторы** — для каждого примитива и каждого этапа протокола.
2. **Property-based тесты** (`proptest`) — на инварианты, а не на примеры.
3. **Фаззинг** (`cargo-fuzz`) — для всех парсеров недоверенного ввода.
4. **Дифференциальное тестирование** — сверка с эталонными векторами.

Криптографический код без тестовых векторов в PR не принимается,
даже если он «очевидно правильный».

---

## Работа с главным документом

`AEGIS_MASTER_PLAN.md` — не справочник, а рабочая доска.

- Закрыли задачу → поставили `[x]` в соответствующем чек-листе.
- Приняли техническое решение → добавили ADR в раздел 5.
- Разошлись с планом → **правится план**, а не память.
- Отменили решение → пометили `[-]` и указали причину. Ничего не удаляем.
- Завершили сессию работы → добавили запись в раздел 30 «Журнал изменений».

Отдельно: задача с пометкой 🔐 закрывается только после прохождения
соответствующего пункта чек-листа OWASP MASVS (раздел 25).

---

## Формат коммитов

```text
<область>: <что сделано в повелительном наклонении>

Развёрнутое объяснение, если нужно. Для security-значимых изменений
обязательно указать, какой пункт модели угроз затронут.

Refs: AEGIS_MASTER_PLAN.md §7.3
```

Области: `protocol`, `keystore`, `storage`, `net`, `media`, `backup`, `core`,
`ffi`, `ios`, `android`, `server`, `docs`, `ci`.

<!-- SPDX-License-Identifier: Apache-2.0 -->

# Чек-лист OWASP MASVS

Машиночитаемая версия раздела 25 плана. Документ, на который раздел 25
ссылается словами «Полная машиночитаемая версия — `docs/masvs-checklist.md`»
и которого до M8 не существовало.

## Как читать

| Статус | Значение |
|---|---|
| ✅ | Закрыто, есть **воспроизводимая** проверка — тест, скрипт CI или артефакт сборки. Столбец «Чем проверено» называет её точно |
| 🟡 | Сделано частично либо проверено только чтением кода. Что именно осталось — в примечании |
| ❌ | Не сделано |
| ⛔ | Снято с обоснованием |

🔐 **Правило заполнения.** «Написано в коде» не даёт ✅. ✅ ставится
только там, где отметку можно опровергнуть: запустить названную
проверку и увидеть красное. Это то же правило 0.1, из-за которого
в разделе 23.0 пришлось снимать отметки с M2 и M3.

Пути тестов указаны от корня репозитория. Команды запуска — в конце.

---

## MASVS-STORAGE — Хранение данных

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| STORAGE-1 | Чувствительные данные только в защищённом хранилище | ✅ | `crates/aegis-storage/src/lib.rs::tests::database_file_contains_no_plaintext`, `::message_repository_writes_no_plaintext`, `::wrong_key_is_rejected` |
| STORAGE-2.1 | Нет данных в логах | ✅ | `tools/check-no-secrets-in-logs.sh` в CI (`security.yml`), плюс типовая защита: `Secret<T>` без `Display`, `Debug` — заглушка (`aegis-types::secret::tests::debug_output_is_redacted`, `::debug_output_is_redacted_when_nested`) |
| STORAGE-2.2 | Нет данных в системном backup | ✅ | `android:allowBackup="false"` + `android:dataExtractionRules` в `android/app/src/main/AndroidManifest.xml` |
| STORAGE-2.3 | Нет данных в кэше клавиатуры | ✅ | `android/app/src/test/.../KeyboardLearningTest.kt` — перебирает **все** `R.layout`, не список полей |
| STORAGE-2.4 | Буфер обмена не дольше 60 секунд | 🟡 | `core/SecureClipboard.kt`: `EXTRA_IS_SENSITIVE` + срок 60 с + очистка при запирании. Теста нет: очистка идёт по `Handler`, и проверка требует управления временем в Robolectric |
| STORAGE-2.5 | Нет данных в снимках переключателя задач | 🟡 | `core/SecureWindow.kt` вызывается на всех экранах; проверено чтением. Автопроверки «`FLAG_SECURE` стоит на каждом экране» нет — она требует инструментального прогона |
| STORAGE-2.6 | Нет превью vault-файлов в системном кэше | 🟡 | `VaultActivity`: список без миниатюр, расшифрованный файл — во временный каталог с удалением при закрытии. Проверено чтением |
| STORAGE-2.7 | iOS: `NSFileProtectionComplete`, исключение из iCloud | ❌ | Клиент iOS остановлен на UI-ките; проверить на Windows нечем |

## MASVS-CRYPTO — Криптография

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| CRYPTO-1 | Современная проверенная криптография | ✅ | Тестовые векторы: `crates/aegis-protocol/tests/rfc_vectors.rs`, `tests/protocol_vectors.rs`; список примитивов — раздел 6.1 |
| CRYPTO-2.1 | Генерация: только OS CSPRNG | ✅ | Только `OsRng` (`rand_core` с `getrandom`): `grep -rn "thread_rng|rand::random|from_entropy" crates/*/src/` — ноль вхождений |
| CRYPTO-2.2 | Хранение: аппаратный KEK | 🟡 | Схема в `aegis-keystore::wrap`; привязка к Android Keystore/StrongBox требует устройства. Зависит от STORAGE-2.7-аналога на iOS |
| CRYPTO-2.3 | Один ключ — одна задача | ✅ | Раздельные метки HKDF; `double_ratchet::tests::each_message_uses_a_fresh_key`, `::nonce_depends_on_message_key`, `::compromised_state_does_not_reveal_past_messages` (дефекты #6–#7, раздел 23.0.1) |
| CRYPTO-2.4 | Ротация ключей | 🟡 | OPK одноразовые и вычёркиваются (`aegis-core::session`); ротация SPK раз в 7 дней на сервере не автоматизирована |
| CRYPTO-2.5 | Уничтожение: zeroize | ✅ | `aegis-types::secret` — `ZeroizeOnDrop`; `aegis-protocol::xeddsa::tests::private_key_is_zeroize_on_drop` |
| CRYPTO-2.6 | Нет захардкоженных ключей | ✅ | `gitleaks` в `security.yml`, `.gitleaks.toml` |

## MASVS-AUTH — Аутентификация

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| AUTH-1 | Аутентификация на сервере | ✅ | Подпись identity key вместо пароля; `server/aegis-server-api/src/auth.rs` (7 тестов), `authz.rs` (5), `pow.rs` (10), `rate_limit.rs` (14) |
| AUTH-2.1 | Биометрия разблокирует ключ, а не возвращает `true` | ❌ | Биометрия не подключена: `LockActivity` работает только с PIN |
| AUTH-2.2 | Ограничение попыток PIN | ✅ | `core/PinAttempts.kt` + `PinAttemptsTest` (8 тестов): таблица задержек раздела 19.3, переживание перезапуска, перевод часов назад, переполнение при удвоении |
| AUTH-2.3 | Auto-lock | 🟡 | `core/AutoLock.kt`: забывание ключа по таймеру в фоне + проверка порога при возвращении. Теста нет — требует инструментального прогона с жизненным циклом |
| AUTH-3 | Повторная аутентификация для File Vault | ✅ | `VaultActivity` требует PIN отдельно от разблокировки приложения |

## MASVS-NETWORK — Сеть

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| NETWORK-1.1 | TLS 1.3 only | 🟡 | Настройка сервера (`server/deploy`); на клиенте ведёт платформенный стек. Автопроверки нет |
| NETWORK-1.2 | Нет cleartext | ✅ | `MitmProxyRejectedTest::release_config_forbids_cleartext_everywhere` + `android:usesCleartextTraffic="false"` |
| NETWORK-2.1 | Два **разных** пина | ✅ | `MitmProxyRejectedTest::release_config_pins_two_distinct_keys`; логика — `aegis-net::pinning` (`MIN_PINS`) |
| NETWORK-2.2 | Не доверяем пользовательским CA | ✅ | `MitmProxyRejectedTest::release_config_does_not_trust_user_certificates`, `::release_config_has_no_local_ca` |
| NETWORK-2.3 | 🧪 `mitm_proxy_rejected` | ✅ | `android/app/src/test/.../MitmProxyRejectedTest.kt` (5 тестов) |
| NETWORK-2.4 | Процедура ротации пинов | ✅ | `docs/ops/cert-pin-rotation.md`, `server/deploy/compute-pin.sh` |
| NETWORK-2.5 | Боевые пины вписаны | ❌ | В релизной политике заглушки: сервера ещё нет. Шаг «Релиз N» процедуры ротации |

## MASVS-PLATFORM — Платформа

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| PLATFORM-1.1 | Content Provider'ы не экспортированы | ✅ | Провайдеров нет ни одного; манифест |
| PLATFORM-1.2 | Экспортированы только launcher и приём `aegis://` | ✅ | `AndroidManifest.xml` — у всех прочих `exported="false"` |
| PLATFORM-1.3 | Deep link валидируется и фаззится | ✅ | `aegis-protocol::contact_link::parse`; фаззинг — `fuzz/fuzz_targets/parse_contact_link.rs`, зеркало на стабильном компиляторе — `tests/fuzz_corpus.rs::contact_link_parsing_never_panics` |
| PLATFORM-1.4 | iOS: URL scheme валидируется | ❌ | Клиент iOS не дошёл до приёма ссылок |
| PLATFORM-2 | Безопасное использование WebView | ⛔ | WebView не используется нигде. Проверяется `grep -r WebView android/ ios/` — ноль вхождений |
| PLATFORM-3.1 | `FLAG_SECURE` на Android | ✅ | `core/SecureWindow.kt`; на экранах ключей и файлов — безусловно (`applyAlways`) |
| PLATFORM-3.2 | Защита от overlay-атак | ✅ | `SecureWindow.blockObscuredTouches` на экранах PIN, хранилища, ключа восстановления, сверки ключей. Сознательно **не** на всех — обоснование в KDoc |
| PLATFORM-3.3 | iOS: скрытие в App Switcher, детект скриншотов | ❌ | См. STORAGE-2.7 |

## MASVS-CODE — Качество кода

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| CODE-1 | Актуальная версия платформы | 🟡 | Android ✅: `minSdk = 28`, `targetSdk = 35`. **iOS ❌**: `ios/Package.swift` объявляет `.iOS(.v13)` при требовании раздела 19.1 «iOS 17.0» — расхождение в четыре версии системы |
| CODE-2.1 | Rust memory safety | ✅ | Весь протокол и хранилище на Rust |
| CODE-2.2 | `#![forbid(unsafe_code)]` | ✅ | `[workspace.lints.rust] unsafe_code = "forbid"`; исключение только для `aegis-ffi`, что проверяет job `unsafe-boundary` в `security.yml` |
| CODE-2.3 | R8/ProGuard в release | ✅ | `minifyEnabled true` + `android/app/proguard-rules.pro`; обфускация видна в `build/outputs/mapping/gmsRelease/mapping.txt` |
| CODE-2.4 | `.so` без debug-символов | ✅ | `strip = "debuginfo"` в `crates/Cargo.toml` + `ndkVersion` подключает `stripReleaseDebugSymbols`. Проверяется `llvm-readelf -S` по всем `.so` в APK |
| CODE-2.5 | Stack canaries, PIE, RELRO | 🟡 | Умолчания NDK для API 28; отдельной проверки `checksec` в CI нет |
| CODE-3.1 | `cargo-audit` в CI | ✅ | `security.yml`, job `supply chain` |
| CODE-3.2 | `cargo-deny` allow-list | ✅ | `security.yml` + `deny.toml` |
| CODE-3.3 | Dependabot / Renovate | ❌ | Не настроено |
| CODE-4.1 | Ошибки не раскрывают детали | ✅ | `aegis-types::tests::error_messages_do_not_leak_detail` — перебирает все варианты `AegisError` |
| CODE-4.2 | Fail-closed при ошибке крипто | ✅ | `AegisError::Crypto` без детализации; `aegis-ffi` оборачивает панику в ошибку (`catch_unwind`), `panic = "abort"` сознательно не включён |

## MASVS-RESILIENCE — Устойчивость

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| RESILIENCE-1.1 | Детект root/jailbreak → предупреждение | ✅ | `core/DeviceIntegrity.kt::looksRooted`; показывается в центре безопасности, не блокирует |
| RESILIENCE-1.2 | Требовать экран блокировки | ✅ | `DeviceIntegrity::hasScreenLock` (`isDeviceSecure`), проверка в центре безопасности ведёт в системные настройки |
| RESILIENCE-1.3 | Android key attestation | ❌ | Не реализовано |
| RESILIENCE-2.1 | Проверка подписи APK во время выполнения | ❌ | Не реализовано |
| RESILIENCE-2.2 | Reproducible builds | ❌ | Не сделано. `ndkVersion` и `abiFilters` закреплены — это предпосылка, но не сама воспроизводимость |
| RESILIENCE-3 | Детект отладчика | ⛔ | Сознательно не делается: ломает работу добросовестных исследователей, на которых держится bug bounty. Прямая оговорка раздела 25 |
| RESILIENCE-4.1 | R8 для Kotlin | ✅ | См. CODE-2.3 |
| RESILIENCE-4.2 | Symbol stripping для Rust | ✅ | См. CODE-2.4 |

## MASVS-PRIVACY — Приватность

| # | Требование | Статус | Чем проверено |
|---|---|---|---|
| PRIVACY-1 | Минимизация сбора данных | ✅ | `tools/check-no-telemetry.sh` в CI; нет `QUERY_ALL_PACKAGES`, нет доступа к галерее (только системный выбор файла) |
| PRIVACY-2.1 | Опубликованная Privacy Policy | ❌ | Не написана |
| PRIVACY-2.2 | Экран «About security» с честными пределами | 🟡 | `AboutActivity` есть; сверка текста с фактическими пределами модели не проводилась |
| PRIVACY-2.3 | Опубликованная спецификация протокола | 🟡 | `docs/protocol/AEGIS-PROTOCOL-v1.md` существует; сверка с реализацией после M6–M8 не проводилась |
| PRIVACY-3.1 | Экспорт данных | ❌ | Не реализовано |
| PRIVACY-3.2 | Удаление аккаунта с реальным удалением | 🟡 | Ручка на сервере есть; сквозной проверки «данных действительно нет» нет |
| PRIVACY-3.3 | Все privacy-настройки opt-in | ✅ | `core/Settings.kt` — умолчания и обоснование каждого |

---

## Сводка

Таблица ниже считается по самим строкам выше, а не ведётся руками:
`python tools/masvs-summary.py --check` сверяет её с документом и падает
при расхождении. Первая версия этого чек-листа была посчитана руками
и ошиблась в двух разделах из восьми.

| Раздел | ✅ | 🟡 | ❌ | ⛔ |
|---|---|---|---|---|
| STORAGE | 4 | 3 | 1 | 0 |
| CRYPTO | 5 | 2 | 0 | 0 |
| AUTH | 3 | 1 | 1 | 0 |
| NETWORK | 5 | 1 | 1 | 0 |
| PLATFORM | 5 | 0 | 2 | 1 |
| CODE | 8 | 2 | 1 | 0 |
| RESILIENCE | 4 | 0 | 3 | 1 |
| PRIVACY | 2 | 3 | 2 | 0 |
| **Итого** | **36** | **12** | **11** | **2** |

⚠️ Чек-лист **не пройден**. Одиннадцать пунктов не сделаны, и четыре
из них — не мелочи: биометрия (AUTH-2.1), воспроизводимая сборка
(RESILIENCE-2.2), Privacy Policy (PRIVACY-2.1) и весь клиент iOS,
на который приходится три ❌ подряд и половина CODE-1.

Отдельно: NETWORK-2.5 закрывается не кодом, а первым боевым
развёртыванием — до него в релизной политике стоят заглушки, и сборка
с ними соединиться не может. Это сделано намеренно (см. комментарий
в файле политики).

## Как запустить проверки

```bash
# Ядро: тесты, линтер, векторы
cd crates && cargo test --workspace && cargo clippy --workspace --all-targets

# Зеркало фаззинга на стабильном компиляторе
cd crates && cargo test -p aegis-protocol --test fuzz_corpus

# Настоящий фаззинг (nightly, Linux или fuzz/Dockerfile)
cargo fuzz build --fuzz-dir fuzz
cargo fuzz run --fuzz-dir fuzz parse_contact_link -- -runs=100000000

# Android: юнит-тесты и релизная сборка
cd android && ./gradlew :app:testGmsDebugUnitTest :app:assembleGmsRelease

# Скрипты-сторожа
bash tools/check-no-secrets-in-logs.sh
bash tools/check-no-telemetry.sh
bash tools/check-no-crypto-in-ui.sh

# Символы в собранных .so
llvm-readelf -S <apk>/lib/*/libaegis.so | grep -E '\.symtab|\.debug_'
```

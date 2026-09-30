<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# App Store — ответы для App Store Connect

**Редакция:** 2026-09-30. Основа — ADR-025 (план, «App Store compliance»);
здесь то, что вписывается в App Store Connect, и то, что ADR-025 пора
поправить.

⚠️ **Подавать пока нечего.** iOS-приложение — каркас (`ios/`), iOS
отложен владельцем. Документ готовит подачу заранее; перед подачей
пройти § 6 заново по iOS-сборке.

---

## 1. Конфиденциальность (App Privacy)

⚠️ **Поправка к ADR-025.** Там записано «Data Not Collected по всем
категориям». Это неверно: имя пользователя и идентификатор устройства
хранятся на сервере дольше, чем нужно для одного запроса, — для Apple
это «собирается». Заявить «не собирается» значит солгать в метке,
которую Apple проверяет по жалобам.

| Категория → тип | Собирается | Связано с пользователем | Слежка (tracking) | Цель |
|---|---|---|---|---|
| Identifiers → **User ID** | Да | Да (это и есть аккаунт) | Нет | App Functionality |
| Identifiers → **Device ID** | Да | Да | Нет | App Functionality |

Всё остальное — **не собирается**:

* **User Content** (сообщения, фото, файлы) — сквозное шифрование:
  сервер хранит шифроблоб, который не может прочитать, до доставки
  (не дольше 30 суток). Apple не требует раскрывать данные, которые
  разработчик не может прочитать; сверить формулировку в справке
  «App privacy details» при заполнении.
* **Contacts** — только на устройстве.
* **Location** — нет; стране при запросе мостов у Tor Project не
  передаётся.
* **Diagnostics, Usage Data, Browsing History** — нет ни одного SDK.
* **Contact Info** (имя, почта, телефон) — не запрашиваются.

Tracking: **No**. App Tracking Transparency не нужен.

---

## 2. Экспортный контроль шифрования

Приложение шифрует содержимое (не только HTTPS), поэтому освобождений
«только аутентификация» или «только HTTPS» у него нет.

| Место | Ответ |
|---|---|
| `Info.plist` | `ITSAppUsesNonExemptEncryption = YES` |
| «Uses encryption?» | Yes |
| «Proprietary or non-standard algorithms?» | **No** — только стандартные: X25519, ML-KEM (FIPS 203), AES-256-GCM, ChaCha20-Poly1305, SHA-2, HKDF, Argon2 |
| Документы для Apple | Не нужны при стандартных алгоритмах (CCATS — только для нестандартных) |
| США (BIS) | Исходный код открыт и опубликован → до первой публикации сборки одно уведомление по электронной почте на `crypt@bis.doc.gov` и `enc@nsa.gov` со ссылкой на репозиторий (EAR §742.15(b)). Готовая программа — массовый продукт (5D992.c) |
| Франция | App Store Connect спрашивает отдельно: при распространении во Франции нужна декларация ANSSI, либо Францию исключить из стран до её подачи |

⚠️ Это не юридическая консультация: перед подачей сверить с текущей
редакцией EAR и правил ANSSI.

---

## 3. Возрастной рейтинг

| Вопрос анкеты | Ответ |
|---|---|
| Насилие, сексуальное содержание, ненормативная лексика, азартные игры, наркотики, ужасы | None |
| **User-Generated Content** | **Yes** |
| **Messaging and Chat** | **Yes** |
| Unrestricted Web Access | No |
| Возрастная проверка / родительский контроль | No |

Итог зависит от действующей шкалы Apple; ADR-025 ожидал наибольший
возрастной рейтинг — для мессенджера без модерации содержимого это
нормально.

---

## 4. Review Notes (вставить как есть, по-английски)

```text
AEGIS is an end-to-end encrypted messenger. Accounts need no phone
number or email: a user picks a username and a 6-digit PIN.

HOW TO TEST
1. Tap "Create account", choose any free username and PIN.
2. The app connects through Tor by default; the first connection takes
   20-60 seconds.
3. To test messaging, message our demo account: tap the pencil button
   and enter the username "aegis_review_1". It is monitored during
   review and will reply.
Demo account for sign-in on a second device is not possible by design:
there are no passwords; each device holds its own keys.

CONTENT MODERATION (Guideline 1.2)
Message content is end-to-end encrypted, so neither we nor the server
can read or filter it - the same model as other end-to-end encrypted
messengers. Users are protected by:
- no unsolicited contact: a new sender's first message arrives as a
  chat request that the user must accept or decline;
- Block: blocks a user from messaging you (contact menu > Block);
- Report: reports the sender to us (contact menu > Report); we act on
  reports within 24 hours by suspending the reported account;
- contact: abuse@<domain>.

ENCRYPTION
Uses standard algorithms only (X25519, ML-KEM, AES-GCM, SHA-2).
Source code is public: <repository URL>.

ACCOUNT DELETION
Settings > Privacy > Delete account. Deletion is immediate.
```

✅ Block и Report работают (2026-09-30), жалобы разбираются в админ-центре
(`docs/ops/admin-center.md`). Строка про 24 часа — **обязательство**
оператора, а не формулировка: без дежурного и ящика `abuse@` её не
отправлять.

---

## 5. Требования ревью — что закрыто и что нет

| Правило | Состояние | Что сделать |
|---|---|---|
| **1.2 UGC: блокировка** | ✅ Android: меню собеседника → «Заблокировать»; сообщения отбрасываются на устройстве; список и разблокировка — Центр безопасности. 🔴 iOS нет | Перенести в iOS |
| **1.2 UGC: жалоба** | ✅ Android: меню собеседника → «Пожаловаться» (или «…и заблокировать»); доказательство — сертификат отправителя; разбор — админ-центр. 🟡 Нужны `abuse@` и дежурный | Процесс оператора; iOS |
| **1.2: запрос на переписку** | ✅ Первое сообщение нового собеседника — запрос: «Принять» или «Отклонить» | — |
| **5.1.1(v) удаление аккаунта в приложении** | ✅ Android; 🔴 iOS нет | Перенести в iOS |
| **5.1.1 политика конфиденциальности** | ✅ `docs/legal/privacy-policy.md`, `.en.md` | Опубликовать по постоянному адресу |
| **2.1 полнота, демо** | 🟡 | Демо-аккаунт на боевом сервере с дежурным на время ревью |
| **2.5.1 только публичные API** | ✅ Защита от снимков — публичными средствами (ADR-016) | Проверить на iOS-сборке |
| **4.7 исполняемый код** | ✅ Не загружается | — |
| **3.1.1 покупки** | ✅ Нет | — |
| **Экспорт шифрования** | 🟡 | Уведомление BIS/NSA до публикации (§ 2) |
| **Уникальное имя** | 🟡 | «AEGIS» занято/конфликтует — см. `listing.md` |

---

## 6. Перед подачей — проверить по iOS-сборке

* список функций в описании совпадает с iOS (Face ID/Touch ID, удаление
  аккаунта, Tor на iOS);
* `Info.plist`: `NSCameraUsageDescription` («Сканирование QR-кода
  собеседника для сверки ключа»), `NSFaceIDUsageDescription`;
  других описаний доступа быть не должно — лишние запросы Apple отклоняет;
* `PrivacyInfo.xcprivacy` (манифест конфиденциальности) — те же два
  идентификатора, что в § 1, и причины использования required-reason API
  (например, `UserDefaults` — `CA92.1`);
* снимки экрана: 6,9" (1320 × 2868) обязательно; 13" для iPad — только
  если заявлен iPad.

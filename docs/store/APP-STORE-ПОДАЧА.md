<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# App Store: от TestFlight до публикации

Состояние на 24 ноября 2026 года. Сборка собирается и выгружается в App
Store Connect одной кнопкой в Codemagic
([ВЫПУСК-ПРИЛОЖЕНИЯ.md](../../server/deploy/ВЫПУСК-ПРИЛОЖЕНИЯ.md), 2.3).
Дальше всё — в [App Store Connect](https://appstoreconnect.apple.com) →
**Apps** → **GasApp**. Справочные ответы (почему так) — в
[app-store.md](app-store.md); тексты витрины — в [listing.md](listing.md).

## 1. TestFlight: поставить себе и проверить

Через 10–30 минут после «Выгружено» сборка появится во вкладке
**TestFlight**.

1. У сборки жёлтое **Missing Compliance** → *Manage*:
   * *What type of encryption algorithms does your app implement?* —
     **Standard encryption algorithms instead of, or in addition to, using
     or accessing the encryption within Apple's operating system**;
   * *Is your app going to be available on the App Store in France?* —
     **No** (Франция исключена, см. § 5);
   * если просят загрузить документ — остановиться и прислать снимок.

   Так — у **каждой** новой сборки, это минута.
2. Слева **Internal Testing** → «+» → группа `Я` → *Testers* → «+» →
   свой Apple ID. Внутренним тестерам (до 100 человек из Users and
   Access) проверка Apple не нужна — сборка доступна сразу.
3. На iPhone: App Store → **TestFlight** → письмо-приглашение →
   *Accept* → *Install*.
4. Проверить до подачи, на **тестовом** аккаунте:
   * создание аккаунта: имя → почта → код из письма → PIN;
   * сообщение iPhone ↔ Android, фото, исчезающие сообщения;
   * статусы: отправляется → отправлено → доставлено → прочитано;
   * профиль собеседника, «Пожаловаться» со скриншотом, «Заблокировать»;
   * вход по Face ID; канал: создать, написать, подписаться по ссылке;
   * **Настройки → Удалить аккаунт** — последним, на тестовом аккаунте.

### Внешние тестеры (по желанию)

**External Testing** → «+» → группа → добавить адреса или включить
*Public Link*. Первую сборку для внешних Apple проверяет (Beta App
Review, обычно до суток); попросит **Test Information**: описание,
почту для отзывов и заметки — те же, что в § 3.

## 2. Аккаунт для проверяющего Apple — за сутки до подачи

Проверяющий заводит свой аккаунт сам, а писать будет **вашему** аккаунту
`gasapp_review_1`. Пароля в GasApp нет — вход это почта и код из письма,
поэтому Apple даётся **ящик**, куда придёт код:

1. Завести отдельный почтовый ящик только для проверки (например, на
   Proton Mail или у почтового провайдера gasapp.eu — `review@…`).
   Без двухфакторной проверки по телефону и без пересылки на вашу почту:
   иначе проверяющий не войдёт или прочитает лишнее. Свою почту не давать.
2. Войти в него один раз из браузера и убедиться, что письмо с кодом
   GasApp туда доходит (зарегистрировать и сразу удалить тестовый
   аккаунт: удаление освобождает адрес).
3. Адрес и пароль ящика — в App Review Information (§ 3). Проверяющий
   может взять и свою почту — в заметках сказано, что можно и так.

Затем:

1. На втором телефоне (или Android) создать аккаунт `gasapp_review_1` —
   **не позже чем за 24 часа** до подачи: по имени новому аккаунту можно
   написать, только когда его ключ сутки пробыл в журнале ключей.
2. Держать телефон с ним под рукой всё время проверки (обычно 1–3 дня):
   первое сообщение проверяющего придёт **запросом** — нажать «Принять»
   и ответить. Молчащий аккаунт — частая причина отказа 2.1.
3. Ящик `abuse@gasapp.eu` должен принимать почту: адрес стоит в заметках
   и в приложении.
4. Серверы обновлены этим выпуском (жалобы с уликами, заморозка) — иначе
   проверяющий увидит прежнее поведение.

## 3. Страница версии: вкладка «App Store» → **1.0 Prepare for Submission**

| Поле | Что вписать |
|---|---|
| **Screenshots → iPhone 6.9"** | 3–10 снимков **1320 × 2868** (портрет). Снять на iPhone в TestFlight-сборке: чаты, переписка, профиль с жалобой, каналы, настройки/безопасность. Если iPhone не Pro Max — прислать снимки, их приведут к нужному размеру. Свои настоящие переписки не показывать |
| Promotional Text | из [listing.md](listing.md) → App Store → «Рекламный текст» (EN) |
| Description | из listing.md → Google Play → «Полное описание» (EN), «отпечаток пальца» → «Face ID / Touch ID» |
| Keywords | из listing.md → «Ключевые слова» (EN) |
| Support URL | `https://gasapp.eu/support/` |
| Marketing URL | `https://gasapp.eu/` |
| Version | `1.0` |
| Copyright | `2026 GasApp` (или ваше имя — как в договоре с Apple) |
| **Build** | «+» → выбрать сборку, прошедшую § 1 |
| App Review Information → **Sign-in required** | **отметить**; *User name* — адрес ящика из § 2, *Password* — пароль **ящика** (не GasApp: в GasApp паролей нет); что это — объяснено в Notes |
| App Review Information → Contact | ваши имя, телефон, почта — видит только Apple |
| App Review Information → **Notes** | текст ниже, как есть |
| Version Release | **Manually release this version** — опубликовать кнопкой после одобрения |

Notes (по-английски, вставить целиком):

```text
GasApp is an end-to-end encrypted messenger with one-author channels.
Accounts need no phone number: pick a username, confirm an email address
with a 6-digit code and set a 6-digit PIN. The server keeps only a hash
of the email.

HOW TO TEST
GasApp has no login with a password: you create a NEW account on your
device. The "User name" and "Password" in the sign-in fields are NOT for
the app - they open a TEST MAILBOX we created for you, at <webmail URL>.
It receives the 6-digit sign-up code. You may also use your own email.
Do not tap "I have a backup": that restores an existing account from
its backup files and is not needed for review.
1. Tap "Get started" > "Create account", choose any free username, enter the test
   mailbox address, then choose any 6-digit PIN. Leave "Connect through
   Tor" off (the default).
2. Open the test mailbox in a browser and enter the 6-digit code from
   the GasApp email (check Spam if it is not in the Inbox).
   If you need to start over: Settings > Delete account frees the
   address for a new sign-up.
3. To test messaging, tap the pencil button and enter the username
   gasapp_review_1. The first message arrives as a chat request; our
   reviewer contact accepts it and replies during the review.
There is no password to share by design: each device holds its own keys.

USER SAFETY (Guideline 1.2)
Message content is end-to-end encrypted: neither we nor the server can
read it. Users are protected by:
- chat requests: a new sender's first message must be accepted;
- Block: chat > tap the name at the top > Block;
- Report: chat > tap the name > Report. The user picks a reason and may
  attach the sender's messages and screenshots; they are encrypted to our
  moderation center only. The server also attaches a signed proof that
  the reported account really messaged the reporter.
- We review reports within 24 hours and can freeze (1-30 days), block
  or delete an account. Contact: abuse@gasapp.eu.

ACCOUNT DELETION
Settings > Delete account. Deletion is immediate and removes the account
from the server.

ENCRYPTION
Standard algorithms only (X25519, ML-KEM, AES-GCM, SHA-2, HKDF).
```

⚠️ «24 hours» — обязательство: жалобы приходят в Telegram из
админ-центра, разбирать их нужно в этот срок.

## 4. App Information (меню слева)

| Поле | Значение |
|---|---|
| Name | сейчас `GasApp Messenger` (так создано приложение). Можно сменить на `GasApp: Encrypted Chat` из listing.md до подачи; после публикации имя меняется только с новой версией |
| Subtitle | `Private chat, no phone number` |
| Primary Category | **Social Networking** |
| Secondary Category | Utilities (необязательно) |
| Privacy Policy URL | `https://gasapp.eu/privacy/` |
| Content Rights | «Does not contain, show, or access third-party content» |
| **Age Rating** → *Edit* | насилие, секс, азарт, наркотики и пр. — **None**; *Messaging and Chat* — **Yes**; *User-Generated Content* — **Yes**; *Unrestricted Web Access* — No; итоговый возраст выставит Apple |

Локализации (Russian, Italian) — правый верхний угол страницы,
необязательно для первой подачи: тексты RU — в listing.md.

## 5. Pricing and Availability

Меню слева, внизу — раздел **MONETIZATION** → *Pricing and
Availability* (меню прокручивается).

⚠️ Блок **App Encryption Documentation → Upload** в App Information
**не трогать**: ответы о шифровании даны у сборки (§ 1), документы при
стандартных алгоритмах не нужны.

* Price: **Free**.
* Availability: все страны и регионы, **кроме France** (решение
  владельца 2026-10-10, см. app-store.md § 2).

## 6. App Privacy (меню слева) → *Get Started*

*Do you or your third-party partners collect data?* — **Yes**, затем:

| Тип | Связано с пользователем | Слежка | Цель |
|---|---|---|---|
| Contact Info → **Email Address** | Yes | No | App Functionality |
| Identifiers → **User ID** | Yes | No | App Functionality |
| Identifiers → **Device ID** | Yes | No | App Functionality |
| User Content → **Photos or Videos** | Yes | No | App Functionality |
| User Content → **Other User Content** | Yes | No | App Functionality |

Последние две — **только** улики в жалобах: скриншоты и сообщения,
которые человек сам решил приложить; их читает оператор. Сами переписки
сервер прочитать не может — их не указывать. Остальное — *not
collected*. Tracking — **No**.

## 7. Экспортный контроль

Ответы в § 1 (Missing Compliance) — всё, что нужно Apple: только
стандартные алгоритмы, документы не загружаются. Отдельного письма в
BIS для стандартной криптографии в массовом продукте с 2021 года не
требуется (EAR § 740.17(b)(1), § 742.15(b) — уведомление только для
нестандартной криптографии). ⚠️ Не юридическая консультация.

## 8. Подать

Вверху страницы версии — **Add for Review** → **Submit for Review**.

* *Waiting for Review* → *In Review* → *Pending Developer Release*
  (одобрено) обычно за 1–3 дня. Письма приходят на почту аккаунта.
* Одобрено → кнопка **Release This Version**: приложение появится в
  App Store в течение суток.
* **Rejected** → App Store Connect → *Resolution Center*: скопировать
  текст отказа целиком и прислать. Не спорить и не переподавать наугад.

## 9. Письмо ITMS-90725 «SDK version issue»

Предупреждение, не отказ: с апреля 2027 года Apple примет только сборки
на iOS 27 SDK (Xcode 27). Делать ничего не нужно — в `codemagic.yaml`
стоит `xcode: latest`, и, когда Xcode 27 выйдет, Codemagic соберёт на нём
сам.

## 10. Следующие версии

Codemagic → *Start new build* → Missing Compliance (§ 1) → во вкладке
App Store «+» у **iOS App** → номер версии (`1.1`) → «Что нового» → новая
сборка → *Submit for Review*. Номер версии меняется в
`ios/project.yml` (`MARKETING_VERSION`).

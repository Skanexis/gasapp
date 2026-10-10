<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Тексты листинга — Google Play и App Store

**Редакция:** 2026-10-07. Каждое поле — в своём блоке: копируется в
консоль магазина как есть. Лимиты проверены скриптом
(`python tools/check-store-listing.py`), длина указана у поля.

🔐 **Правила текста (ADR-026).** Никаких «самый защищённый» и «взломать
невозможно». Каждое утверждение сверяется с кодом и политикой
конфиденциальности; строка про отсутствие аудита обязательна, пока аудита
нет. Постквантовое — только про установление переписки (PQXDH с ML-KEM):
постквантового храповика в продукте нет (план, раздел «SPQR в продукте
не работает»). Звонков, голосовых, групп и push нет — так и написано.

## Название — решение 2026-10-07: GasApp

До 2026-10-07 продукт назывался AEGIS (решение 2026-09-30 оставляло
этот бренд). Владелец переименовал его в **GasApp**.

**GasApp** — везде, где его видит человек после установки: подпись под
значком (`app_name`), экраны приложения, сайт, код. В магазине к нему
добавляется отличающая часть — **«GasApp: Encrypted Chat»** (RU —
«GasApp: шифрованный чат»).

⚠️ **Имя «GasApp» в магазинах не проверено.** Проверка занятости,
сделанная 2026-09-30, относилась к прежнему имени и к новому не
применима. До подачи — проверить заново:

* свободно ли имя в App Store (там оно должно быть уникальным) и нет
  ли в Google Play приложения с тем же именем в категории «Связь»;
* нет ли зарегистрированного товарного знака «GasApp» в классах 9 и 38;
* свободны ли домен и почтовые ящики, названные в политике
  (`privacy@`, `security@`, `abuse@`).

Что остаётся верным при любом имени:

* **«Tor» в названии нельзя**: политика товарного знака Tor Project
  запрещает его в именах продуктов;
* подпись под значком и имя в магазине могут различаться: Apple требует
  лишь, чтобы подпись узнавалась по имени (2.3.8). Имя в магазине
  локализуется — RU в русской витрине, EN в остальных.

---

## Google Play

### Название приложения (≤ 30)

RU:

```text
GasApp: шифрованный чат
```

EN:

```text
GasApp: Encrypted Chat
```

### Краткое описание (≤ 80)

RU:

```text
Мессенджер со сквозным шифрованием: без номера телефона, со встроенным Tor
```

EN:

```text
End-to-end encrypted messenger. No phone number. Tor built in.
```

### Полное описание (≤ 4000)

RU:

```text
GasApp — мессенджер для личной переписки и каналов, в котором сервер не может прочитать ваши сообщения.

БЕЗ НОМЕРА ТЕЛЕФОНА
Аккаунт — это имя пользователя, которое вы придумываете сами. Оно не связано с номером телефона или настоящим именем. Чтобы создать аккаунт, нужен адрес почты: на него придёт код. Сам адрес сервер не хранит — только его хеш.

СКВОЗНОЕ ШИФРОВАНИЕ
Сообщения и файлы шифруются на вашем телефоне и расшифровываются только у собеседника. Протокол открыт: PQXDH и Double Ratchet. В установление переписки входит ML-KEM, поэтому записанный сегодня трафик не расшифровать и будущим квантовым компьютером.

TOR ВСТРОЕН
Включите Tor одним переключателем — и сервер не увидит ваш IP-адрес. Ставить отдельные программы не нужно. Если Tor у вас блокируют, GasApp сам подключится через мосты.

СЕРВЕР ЗНАЕТ МИНИМУМ
• отправитель запечатан (sealed sender): сервер не знает, кто кому пишет;
• IP-адреса не записываются;
• нет аналитики, рекламы и трекеров;
• недоставленное хранится не дольше 30 дней.

ПРОВЕРКА СОБЕСЕДНИКА
Сверьте код безопасности, отсканировав QR-код при встрече. Открытый журнал ключей не даёт серверу незаметно подменить ключ собеседника.

КАНАЛЫ
Читайте каналы по ссылке, QR-коду или @имени: записи с фото и файлами, реакции, закреп, поиск. Закрытые каналы — вход по заявке, которую вы одобряете. Записи и название канала без @имени сервер хранит зашифрованными; публичный канал с @именем сервер прочитать может. На какие каналы подписан аккаунт, сервер знает. Создавать каналы могут аккаунты с премиумом — его выдаёт оператор сервера. Канал — не личная переписка: его читает каждый, у кого есть ссылка.

И ЕЩЁ
• исчезающие сообщения;
• зашифрованное хранилище файлов;
• резервная копия, зашифрованная ключом восстановления, который знаете только вы;
• вход по PIN и отпечатку пальца, защита от снимков экрана;
• удаление аккаунта и выгрузка своих данных прямо из приложения.

ЧЕСТНО О СТАТУСЕ
GasApp — открытый проект, и он ещё не прошёл независимый аудит безопасности. Не полагайтесь на него там, где на кону жизнь или свобода. Исходный код открыт: каждое утверждение выше можно проверить по нему.

Пока нет звонков, голосовых сообщений и групповых чатов. Новые сообщения приходят, пока приложение открыто: push-уведомлений ещё нет.
```

EN:

```text
GasApp is a messenger for private conversations and channels: the server cannot read your messages.

NO PHONE NUMBER
Your account is a username you choose. It is not tied to a phone number or your real name. Creating an account requires an email address: a code is sent to it. The server does not store the address itself, only a hash of it.

END-TO-END ENCRYPTION
Messages and files are encrypted on your phone and decrypted only on your contact's phone. The protocol is open: PQXDH and Double Ratchet. Starting a conversation includes ML-KEM, so traffic recorded today cannot be decrypted by a future quantum computer.

TOR BUILT IN
Turn on Tor with one switch and the server does not see your IP address. There is nothing extra to install. If Tor is blocked where you are, GasApp connects through bridges on its own.

THE SERVER KNOWS AS LITTLE AS POSSIBLE
• the sender is sealed (sealed sender): the server does not know who writes to whom;
• IP addresses are not logged;
• no analytics, no ads, no trackers;
• undelivered messages are kept for 30 days at most.

VERIFY WHO YOU TALK TO
Compare safety numbers by scanning each other's QR code in person. A public key log keeps the server from silently swapping your contact's key.

CHANNELS
Read channels by link, QR code or @name: posts with photos and files, reactions, pinned posts, search. Closed channels are joined by a request you approve. The server stores the posts and title of a channel without an @name encrypted; a public channel with an @name can be read by the server. The server knows which channels an account follows. Channels can be created by premium accounts, granted by the server operator. A channel is not a private conversation: anyone with the link can read it.

ALSO
• disappearing messages;
• encrypted file vault;
• backups encrypted with a recovery key only you know;
• PIN and fingerprint unlock, screenshot protection;
• delete your account or export your data right in the app.

HONEST STATUS
GasApp is an open-source project and has not yet had an independent security audit. Do not rely on it where life or liberty is at stake. The source code is open: every claim above can be checked against it.

Calls, voice messages and group chats are not available yet. New messages arrive while the app is open: there are no push notifications yet.
```

### Что нового (≤ 500)

RU:

```text
Первая открытая бета. Встроенный Tor сам подключается через мосты там, где Tor блокируют.
```

EN:

```text
First public beta. Built-in Tor now connects through bridges on its own where Tor is blocked.
```

---

## App Store

⚠️ iOS-приложение пока не собрано (iOS отложен владельцем). Тексты
готовы заранее; перед подачей сверить список функций с iOS-сборкой —
в частности удаление аккаунта (5.1.1(v)) и вход по Face ID вместо
отпечатка.

### Имя (≤ 30)

RU:

```text
GasApp: шифрованный чат
```

EN:

```text
GasApp: Encrypted Chat
```

### Подзаголовок (≤ 30)

RU:

```text
Шифрование без номера телефона
```

EN:

```text
Private chat, no phone number
```

### Рекламный текст (≤ 170)

RU:

```text
Переписка, которую сервер не может прочитать. Без номера телефона, со встроенным Tor. Открытый код, без рекламы и трекеров.
```

EN:

```text
Conversations the server cannot read. No phone number, Tor built in. Open source, with no ads and no trackers.
```

### Ключевые слова (≤ 100 байт, через запятую без пробелов)

Apple считает байты: кириллица — два байта на букву. Названия чужих
приложений в ключевых словах запрещены (5.2.1).

RU:

```text
шифрование,мессенджер,приватный,чат,tor,e2ee,каналы
```

EN:

```text
encrypted,messenger,private,chat,tor,e2ee,secure,channels,privacy,no phone
```

### Описание (≤ 4000)

Для iOS — то же, что для Google Play, с одной правкой: «вход по PIN
и Face ID / Touch ID» вместо «отпечатка пальца».

### Что нового (≤ 4000)

Как у Google Play.

---

## Адреса (нужны обоим магазинам)

| Поле | Значение | Статус |
|---|---|---|
| Политика конфиденциальности | `https://gasapp.chat/privacy/` — страница из `docs/legal/privacy-policy.md` и `.en.md` | ⚠️ домен и хостинг — решение владельца |
| Удаление аккаунта (Google Play) | `https://gasapp.chat/account-deletion/` — страница из `account-deletion.md` | ⚠️ то же |
| Поддержка (App Store — обязательно) | `https://gasapp.chat/support/` или страница проекта | ⚠️ то же |
| Почта поддержки | `privacy@gasapp.chat`, `security@gasapp.chat` из политики | ⚠️ ящики должны существовать до подачи |
| Стандарты безопасности детей (Google Play) | `https://gasapp.chat/child-safety/` — `child-safety-standards.md` | ⚠️ то же |

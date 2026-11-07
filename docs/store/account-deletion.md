<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Страница «Удаление аккаунта» — для ссылки в Google Play

Опубликовать по постоянному адресу (`https://gasapp.eu/account-deletion/`)
и вписать в Play Console → «Безопасность данных» → «Удаление данных».
Сверено с `docs/legal/data-retention-policy.md` на 2026-09-30.

---

## English

### Delete your GasApp account

**In the app** (the only way to delete an account right away):

1. Open GasApp and unlock it with your PIN.
2. Go to **Settings → Privacy → Delete account**.
3. Confirm twice.

Deletion is immediate. The app shows how many devices, undelivered
messages and attachments were removed.

**Removed from the server:** your username, your identity key, all
devices of the account, prekeys, undelivered messages, notification
tokens and sealed-sender access keys, the hash of your email address,
and every channel you created together with its posts.

**Removed from your phone:** all messages, contacts, keys, vault files
and channels.

**What stays:**

* Posts of your channels that readers already downloaded stay on their
  phones.
* The mail service that delivered your confirmation code keeps its own
  record of that email under its own rules; it is not on our server.

* Messages you already sent stay on your contacts' phones — they are
  end-to-end encrypted and out of our reach.
* Attachments stay on the server until they expire, 30 days after
  upload. Uploads are anonymous, so the server cannot tell which ones
  are yours.
* Your username becomes free for anyone to take. Your contacts will see
  a new safety number if someone else registers it.

### Lost your phone or uninstalled the app?

A GasApp account has no phone number or password, and the email address
you registered with cannot be used to sign in: the server keeps only a
hash of it. The only proof
that an account is yours is the key on your device, so **we cannot verify
a deletion request sent any other way** — and we will not delete an
account on an unverifiable request, because anyone could send one.

* If you have a backup and its recovery key, restore the account on a
  new phone (**Restore my account from a backup**) and delete it there.
* Otherwise, the account is **deleted automatically after 12 months**
  without sign-in, together with everything listed above.

Questions: `privacy@gasapp.eu`.

---

## Русский

### Удаление аккаунта GasApp

**В приложении** (единственный способ удалить аккаунт сразу):

1. Откройте GasApp и введите PIN.
2. **Настройки → Приватность → Удалить аккаунт.**
3. Подтвердите дважды.

Удаление выполняется сразу. Приложение показывает, сколько устройств,
недоставленных сообщений и вложений удалено.

**С сервера удаляются:** имя пользователя, identity-ключ, все устройства
аккаунта, предключи, недоставленные сообщения, токены уведомлений и
ключи доступа sealed sender, хеш адреса почты и все созданные вами
каналы вместе с записями.

**С телефона удаляются:** переписка, контакты, ключи, файлы хранилища
и каналы.

**Что остаётся:**

* Записи ваших каналов, которые читатели уже загрузили, остаются на
  их телефонах.
* У почтовой службы, доставившей письмо с кодом, остаётся её
  собственная запись об этом письме — по её правилам; на нашем
  сервере её нет.

* Отправленные сообщения остаются на телефонах собеседников — они
  зашифрованы сквозным шифрованием, и мы до них не дотягиваемся.
* Вложения остаются на сервере до истечения срока — 30 суток после
  загрузки. Загрузка анонимна: сервер не знает, какие из них ваши.
* Имя пользователя освобождается, и его может занять кто угодно. Если
  это случится, собеседники увидят новый код безопасности.

### Телефон потерян или приложение удалено?

У аккаунта GasApp нет телефона и пароля, а по адресу почты, с которым
вы регистрировались, войти нельзя: сервер хранит только его хеш.
Единственное доказательство, что аккаунт ваш, — ключ на вашем устройстве. Поэтому
**запрос на удаление, отправленный иначе, мы проверить не можем** — и не
удаляем аккаунт по непроверяемому запросу: отправить его мог бы кто угодно.

* Если есть резервная копия и её ключ восстановления — восстановите
  аккаунт на новом телефоне («Восстановить аккаунт из копии») и удалите
  его там.
* Иначе аккаунт **удаляется автоматически через 12 месяцев** без входа —
  вместе со всем перечисленным выше.

Вопросы: `privacy@gasapp.eu`.

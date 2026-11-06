# Пустые пуш-уведомления: Apple (iOS) и Google (Android из Google Play)

Когда приложение закрыто, телефон узнаёт о новом сообщении только через
своего провайдера: Apple на iOS, Google на Android-сборке для Google
Play. GasApp шлёт через них **пустое** уведомление.

## 🔐 Что видят Apple и Google

| Видят | Не видят |
|---|---|
| Что на конкретное устройство что-то пришло, и когда | Текст, отправителя, чат, число сообщений |
| Токен устройства (их же идентификатор) | Имя пользователя GasApp, его контакты |

* Нагрузка постоянная: ключ строки («Новые сообщения»), который телефон
  переводит сам. Сервер не вставляет в пуш ничего, что зависело бы от
  сообщения (`server/gasapp-server-admin/src/push.rs`, тест
  `payloads_are_constant_and_empty_of_content`).
* Одно устройство будится не чаще раза в минуту: серия сообщений — одно
  уведомление, ритм переписки провайдер не видит.
* Токены не попадают в резервные копии и в журналы.
* Сборка `foss` (без Google) пушей не использует: там по-прежнему опрос
  по токену (ADR-040).

⚠️ Это нужно назвать в политике конфиденциальности (`docs/legal/`):
Apple и Google как посредники доставки уведомлений — что они получают
(токен и время) и что нет.

## Как устроено

```text
узел API ──конверт в очередь──▶ PostgreSQL ──NOTIFY gasapp_envelope──▶ gasapp-push (машина базы)
                                                                         │
                                                       Apple APNs ◀──────┤──────▶ Google FCM
                                                           │                         │
                                                         iPhone                   Android
```

Отправщик — команда `gasapp-server-admin push`, служба `gasapp-push` на
машине базы. 🔐 Узлам API интернет запрещён; отправщику он нужен только
до Apple и Google, во внутреннюю сеть хостера его не пускает песочница
(`IPAddressDeny` в юните). Ключи провайдеров лежат только на машине базы.

---

## 1. Ключ Apple (APNs)

1. developer.apple.com → **Certificates, IDs & Profiles** → **Keys** → «+».
2. Имя: `GasApp Push`, отметить **Apple Push Notifications service (APNs)**
   → Continue → Register.
3. **Download** — файл `AuthKey_XXXXXXXXXX.p8`. ⚠️ Скачать можно **один
   раз**. Сразу на флешку: `V:\gasapp\apns-key.p8`.
4. В Bitwarden: **Key ID** (10 символов, на той же странице) и **Team ID**
   (Account → Membership).

Возможность «Push Notifications» для приложения Xcode включит сам при
подписи (в приложении уже стоит `aps-environment`).

## 2. Проект Firebase (Android из Google Play)

1. console.firebase.google.com → **Add project** → имя `GasApp`.
   🔐 На шаге «Google Analytics» — **выключить**.
2. **Add app** → Android → package name **`org.gasapp.app.gms`** (сборка
   для Google Play) → Register. Файл `google-services.json` можно не
   скачивать: приложение настраивается свойствами сборки.
3. **Project settings → General → Your apps** — записать в Bitwarden:
   * **App ID** (`1:1234…:android:abcd…`),
   * **Project ID**,
   * **Web API Key** (вкладка General вверху),
   * **Project number** (= Sender ID).
4. **Project settings → Cloud Messaging**: «Firebase Cloud Messaging API
   (V1)» — **Enabled** (у новых проектов включено).
5. **Project settings → Service accounts → Generate new private key** —
   JSON. 🔐 Это ключ отправки от имени проекта: сразу на флешку,
   `V:\gasapp\fcm-service-account.json`, с ПК удалить.

## 3. Отправщик на машине базы

🖥 **ПК** — посылка (в WSL, флешка подключена):

```bash
source ~/.gasapp-env
K="$OFF/kits/push"; rm -rf "$K"; mkdir -p "$K"
cp "$OFF/apns-key.p8" "$K/apns_key"                        # если есть
cp "$OFF/fcm-service-account.json" "$K/fcm_service_account" # если есть
rsync -a "$K/" gasapp-db:kit/ && rm -rf "$K"
```

🌐 **БАЗА** (впишите Key ID и Team ID):

```bash
sudo -v
sudo install -d -m 700 /etc/gasapp/credentials/push
for f in apns_key fcm_service_account; do
    [ -f ~/kit/$f ] && sudo install -m 600 ~/kit/$f /etc/gasapp/credentials/push/$f
done
shred -u ~/kit/* && rmdir ~/kit
printf 'GASAPP_APNS_KEY_ID=%s\nGASAPP_APNS_TEAM_ID=%s\nGASAPP_APNS_TOPIC=org.gasapp.messenger\n' \
    ВАШ_KEY_ID ВАШ_TEAM_ID | sudo install -m 644 /dev/stdin /etc/gasapp/push.env
sudo install -m 644 ~/deploy/systemd/gasapp-push.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now gasapp-push
sudo journalctl -u gasapp-push -n 5 --no-pager
```

✅ В журнале: `отправщик пушей запускается apns=true fcm=true` и
`отправщик пушей слушает канал конвертов`.

Затем в `/etc/gasapp/monitor.env` на БАЗЕ добавить `gasapp-push`
в `GASAPP_UNITS` — монитор сообщит, если служба упадёт.

> Исходящий доступ к Apple и Google с машины базы открыт по умолчанию
> (`ufw default allow outgoing`). Порт 443 наружу — всё, что нужно.

## 4. Сборки приложений

**iOS** — ничего дополнительно: токен регистрируется после входа по PIN.
Сборка из Xcode получает токен **песочницы** APNs (провайдер
`apns-sandbox`), TestFlight и App Store — боевой (`apns`); отправщик
различает их сам.

**Android (Google Play)** — к сборке `bundleGmsRelease` добавить значения
из шага 2.3:

```powershell
.\gradlew.bat bundleGmsRelease @common `
    -PgasappFcmProjectId=gasapp-xxxxx `
    -PgasappFcmAppId=1:1234567890:android:abcdef `
    -PgasappFcmApiKey=AIza… `
    -PgasappFcmSenderId=1234567890 `
    "-PgasappSigningCertSha256=…"
```

Без этих значений сборка работает как раньше: опрос сервера по токену.

## 5. Проверка

1. Два телефона. На втором — закрыть GasApp (смахнуть из недавних).
2. С первого — сообщение второму.
3. ✅ Через несколько секунд на втором — «Новые сообщения». В тексте
   уведомления — **ничего**, кроме этих слов.
4. Второе сообщение подряд — нового уведомления нет (раз в минуту).

❌ Не пришло:

| Где смотреть | Что значит |
|---|---|
| `journalctl -u gasapp-push` → `пуш не отправлен provider=apns … 403` | Неверные Key ID / Team ID или ключ `.p8` |
| `… provider=apns-sandbox …` с TestFlight | Сборка из Xcode и TestFlight — разные окружения: переустановить из TestFlight и войти по PIN |
| `… provider=fcm … 403` | Не включён FCM API V1 или не тот JSON сервисного аккаунта |
| В журнале пусто | Токена нет: в приложении выключены уведомления или не дано разрешение |

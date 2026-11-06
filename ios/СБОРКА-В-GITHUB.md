# iOS без своего Mac: GitHub Actions → TestFlight → ваш iPhone

GitHub даёт macOS-машины с Xcode. На них проект собирается, проверяется
в симуляторе (снимки каждого экрана), а по кнопке — подписывается и
уходит в **TestFlight**. Оттуда приложение ставится на iPhone приложением
TestFlight. Mac не нужен вообще.

Workflow — `.github/workflows/ios.yml`.

## Цена

* **Публичный репозиторий** — минуты macOS бесплатны.
* **Приватный** — в бесплатном тарифе 2000 минут в месяц, но минута macOS
  считается за 10: это около 200 минут macOS. Первая сборка ~40 минут,
  следующие с кешем — ~15–20. Сверх лимита — оплата по тарифу GitHub
  (Settings → Billing).

---

## Шаг 1. Репозиторий на GitHub

1. github.com → войти (🔐 двухфакторная защита: Settings → Password and
   authentication).
2. «+» → **New repository** → имя `gasapp` → **Private** или **Public**
   → **без** README и .gitignore → Create.
3. 🪟 PowerShell, папка проекта (адрес — свой):

```powershell
cd C:\Users\be4ho\Desktop\WORK\AEGIS
git remote add origin https://github.com/ВАШ_ЛОГИН/gasapp.git
git push -u origin gasapp
```

При первом `push` откроется окно входа в GitHub (Git Credential Manager).

🔐 Перед первым `push`: в репозитории нет секретов (ключи и пароли — на
флешке и в Bitwarden), `bundle.conf` и `Local.xcconfig` в `.gitignore`.
Проверка: `git ls-files | Select-String "bundle.conf$|Local.xcconfig$|\.jks$|\.p8$"` — пусто.

## Шаг 2. Проверка в симуляторе — сама

После `push` — вкладка **Actions** → **ios** → запуск. Через 20–40 минут:

* ✅ зелёная галочка — собралось и запустилось на всех экранах;
* ❌ красный крест — внизу запуска **Artifacts → mac-report**: скачать
  архив и прислать (или положить в папку проекта) — там все ошибки
  сразу (`swift-errors.txt`, `build-errors.txt`) и снимки экранов.

Запускается сама на каждый `push`, где менялись `ios/`, ядро или скрипты.

## Шаг 3. TestFlight — один раз настроить

### 3.1. Приложение в App Store Connect

appstoreconnect.apple.com → **Apps** → «+» → **New App**:

* Platform: **iOS**; Name: **GasApp** (если занято — «GasApp Messenger»);
* Primary language: Russian;
* Bundle ID: **org.gasapp.messenger** — если его нет в списке:
  developer.apple.com → Identifiers → «+» → App IDs → App → Bundle ID
  explicit `org.gasapp.messenger`, отметить **Push Notifications** →
  Register; затем вернуться и выбрать;
* SKU: `gasapp-ios`.

### 3.2. Ключ API App Store Connect

appstoreconnect.apple.com → **Users and Access** → **Integrations** →
**App Store Connect API** → **Team Keys** → «+»:

* Name: `GitHub CI`; Access: **Admin** (нужно для подписи в облаке);
* **Download API Key** — файл `AuthKey_XXXXXXXXXX.p8`, ⚠️ скачивается
  **один раз** → на флешку;
* записать **Key ID** и **Issuer ID** (вверху страницы).

🔐 Ключ Admin позволяет выпускать сборки от имени вашей команды. Храните
его только в секретах GitHub и на флешке. Утёк — там же **Revoke**.

### 3.3. Секреты в GitHub

Репозиторий → **Settings** → **Secrets and variables** → **Actions** →
**New repository secret** — по одному:

| Имя | Значение |
|---|---|
| `APPLE_TEAM_ID` | Team ID (developer.apple.com → Account → Membership) |
| `ASC_KEY_ID` | Key ID из 3.2 |
| `ASC_ISSUER_ID` | Issuer ID из 3.2 |
| `ASC_KEY_P8` | содержимое файла `AuthKey_….p8` **целиком**, с строками `-----BEGIN/END PRIVATE KEY-----` |
| `GASAPP_PINS` | `основной_пин,запасной_пин` — из `V:\gasapp\pin-primary.txt` и `pin-backup.txt` |
| `GASAPP_SERVER_ONION` | onion-адрес `….onion:443` (если есть) |

Секреты видят только запуски в вашем репозитории; в журнал они не
выводятся.

## Шаг 4. Сборка в TestFlight

**Actions** → **ios** → **Run workflow** → ветка `gasapp` → галочка
**testflight** → **Run workflow**.

Сначала пройдёт проверка, затем — релизная сборка, подпись и выгрузка.
Через 10–30 минут после зелёной галочки сборка появится в
App Store Connect → **TestFlight** (статус «Processing», потом готова).

* **Missing Compliance** (шифрование) — один раз ответить: приложение
  использует шифрование → стандартные алгоритмы, освобождение для
  массового рынка. Ответ запоминается в настройках приложения.
* **Internal Testing** → «+» → группа `Я` → добавить себя (свой Apple ID).

## Шаг 5. На iPhone

1. App Store → установить **TestFlight**.
2. Письмо-приглашение или ссылка в TestFlight → **Accept** → **Install**.
3. GasApp на телефоне. Каждая новая сборка приходит туда же — кнопка
   **Update**.

> ⚠️ С заглушками пинов релиз не соберётся (проверка в `project.yml`):
> `GASAPP_PINS` — настоящие пины вашего сервера. Пока сервер не развёрнут,
> приложение откроется, но к серверу не подключится.

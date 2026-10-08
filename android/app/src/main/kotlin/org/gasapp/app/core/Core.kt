// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.content.Context
import java.io.File
import org.gasapp.app.BuildConfig
import org.gasapp.app.net.EmbeddedTor
import org.gasapp.app.net.NetworkProxy
import org.gasapp.app.net.PlatformTransport
import uniffi.gasapp.deriveStorageKey
import uniffi.gasapp.deriveStorageKeyBound
import uniffi.gasapp.deriveStorageKeyTee
import uniffi.gasapp.generateStorageSalt
import uniffi.gasapp.Messenger

/**
 * Единая точка доступа к ядру.
 *
 * # Почему один экземпляр на процесс
 *
 * `Messenger` владеет открытым хранилищем. Второй экземпляр открыл бы
 * ту же базу второй раз, и два состояния Double Ratchet начали бы
 * расходиться: сообщение, зашифрованное одним, не расшифровалось бы
 * другим. SQLite это не запрещает, поэтому ограничение приходится
 * держать здесь.
 *
 * 🔐 Ключ базы выводится из PIN **и** секрета, не покидающего
 * устройство ([unlock]). Нулевым он не был уже к M4, а к M8 перестал
 * быть и «только из PIN»: одного PIN хватало ровно на пару часов
 * перебора по снятому файлу (P-5, раздел 23.6).
 */
object Core {

    private var messenger: Messenger? = null

    /** Отпечаток ключа открытой базы — для проверки PIN (см. [keyOpensStorage]). */
    private val openedKey = OpenedKey()

    /**
     * Идентификатор устройства, выданный сервером при регистрации.
     *
     * Читается из хранилища, а не хранится только в памяти: память
     * пуста после перезапуска, и приложение переставало забирать
     * очередь сообщений — ручка приёма адресуется по устройству.
     *
     * Значение кешируется на время сессии: обращение к нему идёт
     * из onStart каждого экрана, а поход в зашифрованную базу за одной
     * и той же строкой каждый раз ничего не даёт.
     */
    val deviceId: String?
        @Synchronized get() {
            cachedDeviceId?.let { return it }

            val stored = runCatching { messenger?.ownDeviceId() }.getOrNull()
            cachedDeviceId = stored

            return stored
        }

    private var cachedDeviceId: String? = null

    /**
     * Возвращает мессенджер, открывая хранилище при первом обращении.
     *
     * 🔐 `key` — результат растягивания PIN через `deriveStorageKey`.
     * Неверный PIN даёт неверный ключ, и SQLCipher просто не откроет
     * базу: отдельной проверки правильности не существует, потому что
     * она означала бы хранить где-то признак верного PIN — подсказку
     * для перебора.
     */
    @Synchronized
    fun open(context: Context, key: ByteArray): Messenger {
        messenger?.let { return it }

        val opened = Messenger.open(
            databasePath = databasePath(context),
            databaseKey = key,
            transport = PlatformTransport(BuildConfig.GASAPP_SERVER_URL),
        )

        messenger = opened
        openedKey.remember(key)

        // 🔐 Прокси применяется сразу после открытия базы — до первого
        // сетевого запроса. Настройка живёт в зашифрованной базе, поэтому
        // раньше её прочитать нечем; а после — уже поздно: запрос, ушедший
        // напрямую при включённом Tor, выдал бы адрес. Нечитаемая настройка
        // закрывает сеть, а не открывает её.
        // Мосты с экрана регистрации — в базу до применения режима:
        // см. EmbeddedTor.pendingBridges.
        EmbeddedTor.takePendingBridges()?.let { text -> runCatching { opened.setTorBridges(text) } }

        NetworkProxy.apply(
            context,
            runCatching { opened.proxy() }.getOrNull(),
            runCatching { opened.torBridges() }.getOrNull(),
        )

        // 🔐 Чистка истёкших сообщений сразу после открытия базы.
        //
        // Таймер в приложении работает, только пока оно запущено:
        // сообщение с часовым сроком, полученное перед тем, как телефон
        // убрали на неделю, пережило бы свой срок в семь раз. Изъятие
        // устройства показало бы переписку, которую пользователь
        // считает исчезнувшей.
        //
        // Ошибка чистки не мешает открыть хранилище: недоступная база
        // — уже отдельная проблема, и падать здесь значило бы лишить
        // пользователя приложения из-за уборки.
        runCatching { opened.purgeExpired(System.currentTimeMillis()) }

        // 🔐 Подмести расшифрованные файлы хранилища, оставшиеся
        // от прошлого сеанса.
        //
        // `VaultActivity.onStop` удаляет их по списку в памяти,
        // но после гибели процесса списка нет, а файлы есть.
        // Здесь список заведомо пуст, и чистить можно по каталогу.
        runCatching { VaultTemp.sweep(context) }

        // 🔐 Пополнение одноразовых предключей.
        //
        // Одноразовый предключ расходуется при каждом первом контакте:
        // сервер отдаёт его тому, кто начинает переписку, и вычёркивает.
        // Без пополнения пул кончается, и каждая новая переписка
        // заводится без одноразового ключа — теряя и классическую,
        // и пост-квантовую половину его вклада в forward secrecy.
        // Сервер при этом отвечает успехом, и никто ничего не замечает.
        //
        // Здесь же ротируется подписанный предключ, если вышел срок:
        // обе задачи решаются одним запросом.
        //
        // ⚠️ В фоне и без ожидания: обслуживание ходит в сеть, а этот
        // метод вызывается из главного потока при открытии базы.
        // Ошибка не мешает работать — пул починится при следующем
        // открытии, а падать здесь значило бы не пустить человека
        // в переписку из-за не дошедшего запроса.
        maintainPrekeys(opened)

        return opened
    }

    /**
     * 🔐 Обслуживание предключей сразу после регистрации.
     *
     * При открытии базы обслуживание уже запускалось — но до регистрации,
     * когда ключей устройства ещё не было. Поток падал, `runCatching`
     * молча это глотал, и новый аккаунт жил с **одним** одноразовым
     * ключом каждого вида до первого повторного входа: первый незнакомец
     * его забирал, остальные первые контакты шли без него.
     *
     * Нашлось на эмуляторе: после регистрации на сервере лежало 1 + 1,
     * после входа по PIN — 100 + 100.
     */
    @Synchronized
    fun maintainPrekeysNow() {
        messenger?.let(::maintainPrekeys)
    }

    /**
     * Обслуживает предключи в фоне.
     *
     * Отдельным потоком, а не корутиной: [Core] не знает про область
     * жизни экрана, а обслуживание переживает любой из них.
     */
    private fun maintainPrekeys(messenger: Messenger) {
        Thread {
            runCatching { messenger.maintainPrekeys(System.currentTimeMillis()) }
        }.apply {
            // Демон: незавершённое обслуживание не должно удерживать
            // процесс.
            isDaemon = true
            name = "gasapp-prekeys"
        }.start()
    }

    /**
     * 🔐 Открывает хранилище по PIN.
     *
     * Единственная точка, где строится ключ базы. До M8 их было две —
     * экран регистрации и экран блокировки, — и вторая ключ вовсе
     * не строила (см. историю `LockActivity.unlock`).
     *
     * # Из чего состоит ключ (схема v3)
     *
     * Из растянутого `Argon2id` PIN и ответа Android Keystore на него
     * ([TeeKey]) — цепочки HMAC невынимаемым ключом. Каждая попытка
     * перебора требует самого телефона, идёт по очереди и не
     * переносится на видеокарты.
     *
     * # Переход со старых схем
     *
     * * v1 — ключ из одного PIN;
     * * v2 — PIN и 32 байта [HardwareKey], которые расшифровывались
     *   в память приложения: достав их один раз, PIN перебирали вне
     *   телефона за часы.
     *
     * Старая база открывается прежним ключом и **сразу**
     * перешифровывается ключом v3 ([Messenger.rekeyStorage]); секрет v2
     * после этого уничтожается.
     *
     * Сначала всегда пробуется v3: так прерванный переход (база уже
     * перешифрована, а старый секрет не успели удалить) не запирает
     * человека — база откроется первой же попыткой, а остаток старой
     * схемы уберётся здесь же.
     *
     * 🔐 Порядок внутри перехода обязателен: сначала успешное
     * открытие, потом смена ключа. Перешифровать можно только то, что
     * удалось расшифровать, а смена ключа на неоткрытой базе
     * превратила бы её в нечитаемую ничем.
     */
    @Synchronized
    fun unlock(context: Context, pin: ByteArray): Messenger {
        // 🔐 Открытый мессенджер не возвращается как есть: вход — это
        // проверка PIN, и проверяет её только открытие базы этим PIN.
        // Прежде здесь стояло `messenger?.let { return it }`, и любой
        // PIN «открывал» уже открытое: экран входа, показанный поверх
        // незапертого приложения, принимал что угодно и сбрасывал
        // счётчик неверных попыток, а повторная регистрация с другим
        // PIN оставалась на базе под первым.
        close()

        val salt = salt(context)
        val stretched = deriveStorageKey(pin, salt)

        try {
            val key = teeKey(stretched, salt)
            val current = runCatching { open(context, key) }

            current.getOrNull()?.let { opened ->
                retireLegacy(context)
                establishVaultVerifier(opened, pin, salt)
                return opened
            }

            // Новой базы старые схемы не касаются: отказ — настоящий.
            if (!hasAccount(context)) throw current.exceptionOrNull() ?: IllegalStateException()

            for (legacyKey in legacyKeys(context, stretched, salt)) {
                val opened = runCatching { open(context, legacyKey) }.getOrNull() ?: continue

                opened.rekeyStorage(key)
                openedKey.remember(key)
                // В биометрическом конверте лежит прежний ключ — открыть
                // перешифрованную базу он уже не сможет. Включить заново —
                // в настройках приватности.
                runCatching { BiometricUnlock.disable(context) }
                retireLegacy(context)
                establishVaultVerifier(opened, pin, salt)

                return opened
            }

            // Неверный PIN: ни одна схема не открыла базу.
            throw current.exceptionOrNull() ?: IllegalStateException()
        } finally {
            stretched.fill(0)
        }
    }

    /** Ключи старых схем, от новой к старой (см. [unlock]). */
    private fun legacyKeys(context: Context, stretched: ByteArray, salt: ByteArray): List<ByteArray> =
        buildList {
            // Только если секрет v2 уже есть: `HardwareKey.secret`
            // создаёт его при отсутствии.
            if (HardwareKey.exists(context)) {
                runCatching { deriveStorageKeyBound(stretched, salt, HardwareKey.secret(context)) }
                    .getOrNull()
                    ?.let(::add)
            }
            // v1: ключ — сам растянутый PIN.
            add(stretched.copyOf())
        }

    /**
     * 🔐 Уничтожает секрет схемы v2 — только когда база уже открыта
     * ключом v3. Пока он лежит, достать его и перебирать PIN вне
     * телефона по старой копии базы всё ещё можно.
     */
    private fun retireLegacy(context: Context) {
        if (!HardwareKey.exists(context)) return

        runCatching {
            HardwareKey.destroy()
            HardwareKey.deleteSecretFile(context)
        }
    }

    /** Ключ схемы v3 из растянутого PIN. */
    private fun teeKey(stretched: ByteArray, salt: ByteArray): ByteArray {
        val response = TeeKey.respond(stretched)
        try {
            return deriveStorageKeyTee(stretched, salt, response)
        } finally {
            response.fill(0)
        }
    }

    /**
     * 🔐 Заводит проверочное значение File Vault.
     *
     * Здесь, а не на экране хранилища: база только что открылась этим
     * PIN, и это единственный момент, когда он заведомо верен. Прежде
     * vault «открывал» любой PIN — список имён отдавался, удаление
     * работало.
     *
     * Ошибка не мешает войти: vault, у которого значения нет,
     * сверяет PIN с ключом своих файлов.
     */
    private fun establishVaultVerifier(messenger: Messenger, pin: ByteArray, salt: ByteArray) {
        runCatching { messenger.establishVaultVerifier(pin, salt) }
    }

    /**
     * 🔐 Собирает ключ базы из PIN и аппаратного секрета.
     *
     * Единственное место, где ключ строится. Вызывается из [unlock]
     * и из настройки биометрии: две отдельные сборки разошлись бы,
     * и одна из них открывала бы базу слабее другой.
     *
     * # ⚠️ Почему это публично
     *
     * Ради включения биометрии: чтобы запечатать ключ базы в конверт
     * Keystore ([BiometricUnlock]), его надо сначала получить, а PIN
     * в этот момент у пользователя уже спрошен.
     *
     * Других вызывающих быть не должно. Открывать хранилище этим
     * ключом напрямую не нужно — для этого есть [unlock] и [open],
     * и только они знают про переход со старых баз.
     */
    fun deriveKey(context: Context, pin: ByteArray): ByteArray {
        val salt = salt(context)
        val stretched = deriveStorageKey(pin, salt)
        try {
            return teeKey(stretched, salt)
        } finally {
            stretched.fill(0)
        }
    }

    /**
     * 🔐 Открыта ли база именно этим ключом.
     *
     * Для включения биометрии: ключ, выведенный из введённого PIN,
     * запечатывается в конверт Keystore только если он и открывает
     * базу. Прежде он запечатывался как есть — опечатка в PIN давала
     * «включённую» биометрию, которая базу не открывала никогда.
     */
    @Synchronized
    fun keyOpensStorage(key: ByteArray): Boolean = openedKey.matches(key)

    /**
     * 🔐 Открывает хранилище ключом из биометрического конверта.
     *
     * Отличается от [unlock] тем, что PIN здесь неоткуда взять:
     * ключ приходит готовым, уже расшифрованным после подтверждения.
     *
     * ⚠️ Перехода со старых баз здесь нет, и он не нужен: конверт
     * заводится только после успешного входа по PIN, а тот переход
     * уже выполнил.
     */
    @Synchronized
    fun unlockWithKey(context: Context, key: ByteArray): Messenger = open(context, key)

    /**
     * Возвращает уже открытый мессенджер.
     *
     * 🔐 Бросает исключение, если хранилище закрыто: открыть его без
     * PIN нельзя, и молчаливое открытие с нулевым ключом было бы
     * ровно той дырой, которую закрывает эта правка.
     */
    @Synchronized
    fun messenger(): Messenger =
        messenger ?: error("хранилище закрыто: сначала введите PIN")

    /** Открыто ли хранилище. */
    val isUnlocked: Boolean
        @Synchronized get() = messenger != null

    /**
     * Соль для растягивания PIN.
     *
     * Лежит рядом с базой открытым текстом: она защищает не от того,
     * кто получил устройство, а от заранее посчитанных таблиц.
     */
    @Synchronized
    fun salt(context: Context): ByteArray {
        val file = File(context.filesDir, SALT_NAME)

        // Пустой файл — след сбоя питания в прежней версии, писавшей
        // без fsync (см. DurableFile): соли в нём нет, и считать его
        // солью значило бы навсегда заблокировать регистрацию.
        if (file.exists() && file.length() > 0) {
            return file.readBytes()
        }

        val fresh = generateStorageSalt()
        DurableFile.write(file, fresh)

        return fresh
    }

    /**
     * Запоминает устройство после регистрации.
     *
     * Ядро уже записало его в хранилище; здесь значение попадает
     * в кеш, чтобы первый же экран после регистрации не ходил
     * за ним в базу.
     */
    @Synchronized
    fun rememberDevice(id: String) {
        cachedDeviceId = id
    }

    /** Заведён ли аккаунт на этом устройстве. */
    fun hasAccount(context: Context): Boolean = File(databasePath(context)).exists()

    /**
     * 🔐 Закрывает хранилище при блокировке.
     *
     * После этого ключ базы больше не удерживается в памяти процесса,
     * и следующее обращение потребует открыть её заново.
     */
    @Synchronized
    fun close() {
        messenger?.close()
        messenger = null
        openedKey.forget()

        // 🔐 Повторный PIN, подтверждённый до запирания, после него
        // не действует: окно в минуту — для цепочки действий владельца,
        // а не для того, кто взял телефон после автоблокировки.
        Reauth.forget()

        // 🔐 Кеш сбрасывается вместе с хранилищем: идентификатор
        // устройства — это сведение об аккаунте, и держать его после
        // блокировки значит оставлять след того, кто пользовался
        // телефоном.
        cachedDeviceId = null
    }

    private fun databasePath(context: Context): String =
        File(context.filesDir, DATABASE_NAME).absolutePath

    /** Имя файла базы. */
    private const val DATABASE_NAME = "gasapp.db"

    /** Имя файла соли. */
    private const val SALT_NAME = "gasapp.salt"

}

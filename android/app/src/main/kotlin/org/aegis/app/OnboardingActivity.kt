// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisTextField
import org.aegis.app.components.PinPad
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.Core
import org.aegis.app.core.Pin
import org.aegis.app.core.SecureWindow
import org.aegis.app.net.NetworkProxy
import uniffi.aegis.FfiException
import uniffi.aegis.FfiProxy
import uniffi.aegis.canonicalUsername

/**
 * Онбординг: регистрация первого аккаунта.
 *
 * 🔐 Предупреждение об отсутствии аудита показывается **до** кнопки
 * и тем же кеглем, что и остальной текст (раздел 21 плана). Мессенджер,
 * обещающий защиту, которую не проверял никто посторонний, обязан
 * сказать об этом до того, как пользователь начнёт ему доверять.
 */
class OnboardingActivity : AppCompatActivity() {

    private lateinit var username: AegisTextField
    private lateinit var pin: PinPad
    private lateinit var error: TextView
    private lateinit var progress: ProgressBar
    private lateinit var progressLabel: TextView
    private lateinit var createButton: AegisButton
    private lateinit var direct: SwitchCompat
    private lateinit var openOrbot: AegisButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_onboarding)

        username = findViewById(R.id.onboarding_username)
        // 🔐 PIN — своей клавиатурой, не системной (см. [PinPad]).
        pin = PinPad(findViewById(android.R.id.content))
        error = findViewById(R.id.onboarding_error)
        progress = findViewById(R.id.onboarding_progress)
        progressLabel = findViewById(R.id.onboarding_progress_label)
        createButton = findViewById(R.id.onboarding_create)

        direct = findViewById(R.id.onboarding_direct)
        openOrbot = findViewById(R.id.onboarding_open_orbot)

        createButton.setOnClickListener { register() }
        findViewById<AegisButton>(R.id.onboarding_recover).setOnClickListener { startRecovery() }
        openOrbot.setOnClickListener { launchOrbot() }

        direct.setOnCheckedChangeListener { _, checked ->
            findViewById<TextView>(R.id.onboarding_network_hint).setText(
                if (checked) R.string.onboarding_network_direct else R.string.onboarding_network_tor,
            )
        }
    }

    private fun register() {
        // 🔐 Правило имени — ядра, а не экрана: строчные латинские буквы,
        // цифры и `_`. Двойник «аlice» с кириллической «а» здесь
        // отвергается, а «Alice» становится «alice».
        val raw = username.text?.toString().orEmpty()
        val name = try {
            canonicalUsername(raw)
        } catch (_: FfiException) {
            showError(getString(R.string.onboarding_error_username))

            return
        } catch (_: LinkageError) {
            // Ядро не загрузилось — это не ошибка имени. Регистрация ниже
            // упадёт на том же и сотрёт базу, как при любом сбое.
            raw.trim()
        }

        if (!pin.isComplete) {
            showError(getString(R.string.onboarding_error_pin))

            return
        }

        // Забирается с затиранием буфера: клавиатура PIN не хранит.
        val pinValue = pin.take()

        // 🔐 Ровно то, что способен набрать экран входа.
        //
        // Прежде здесь стояло «не короче шести», а поле принимало
        // до двенадцати. PIN длиннее шести давал ключ, который
        // экран входа не воспроизведёт никогда, — база не
        // открывалась больше ни разу (см. [Pin]).
        if (!Pin.isAcceptable(pinValue)) {
            showError(getString(R.string.onboarding_error_pin))

            return
        }

        // 🔐 Выбор сети берётся один раз, до работы: переключатель
        // на время регистрации заблокирован.
        val viaTor = !direct.isChecked

        setWorking(true)

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    // 🔐 Ключ хранилища выводится из PIN через Argon2id
                    // и связывается с секретом, не покидающим устройство
                    // (Core.unlock). Занимает около секунды и идёт
                    // в фоновом потоке.
                    //
                    // Цена этой секунды — то, что снятый с телефона файл
                    // базы не перебирается: одного PIN для ключа мало.
                    //
                    // Общий экземпляр: второй открыл бы ту же базу
                    // повторно, и состояния Double Ratchet разошлись бы.
                    val messenger = Core.unlock(this@OnboardingActivity, pinValue)

                    // 🔐 У новой базы режим по умолчанию — Tor через Orbot:
                    // его уже применил Core.unlock. Прямое соединение —
                    // только если человек выбрал его сам, и до первого
                    // запроса: регистрация — первое, что видит сервер.
                    if (!viaTor) {
                        messenger.setProxy(FfiProxy.Direct)
                        NetworkProxy.apply(FfiProxy.Direct)
                    }

                    messenger
                        .register(name, System.currentTimeMillis())
                        .also { Core.maintainPrekeysNow() }
                }.onFailure {
                    // 🔐 Незарегистрированная база стирается.
                    //
                    // Прежде она оставалась — открытой и под ключом
                    // из первого PIN. Повторная попытка с другим PIN
                    // получала тот же открытый мессенджер: аккаунт
                    // регистрировался, а база так и оставалась под
                    // первым PIN, который человек уже считал
                    // сменённым, — после блокировки новый PIN её
                    // не открывал, и счётчик неверных попыток вёл
                    // к стиранию. А после перезапуска существующий
                    // файл базы выглядел аккаунтом: вместо регистрации
                    // открывался экран входа — в базу, где аккаунта нет.
                    //
                    // Сюда приходят только сбои открытия и регистрации:
                    // пополнение предключей идёт в фоне и не бросает.
                    AccountWipe.wipe(this@OnboardingActivity)
                }
            }

            setWorking(false)

            result
                .onSuccess { account ->
                    // Устройство запоминается для приёма: конверты
                    // адресуются по нему, а не по аккаунту.
                    Core.rememberDevice(account.deviceId)

                    startActivity(
                        Intent(this@OnboardingActivity, ChatListActivity::class.java)
                            .putExtra(EXTRA_DEVICE_ID, account.deviceId),
                    )
                    finish()
                }
                .onFailure { failure ->
                    // Текст ошибки ядра намеренно неинформативен, поэтому
                    // показывается собственная строка. Различать «имя
                    // занято» и «сервер недоступен» здесь можно только
                    // по типу исключения.
                    //
                    // 🔐 Через Tor сбой сети чаще всего значит, что Orbot
                    // не запущен. Напрямую приложение само не уходит:
                    // человек либо запускает Orbot, либо явно выбирает
                    // прямое соединение.
                    val network = failure is FfiException

                    showError(
                        when {
                            network && viaTor -> getString(R.string.onboarding_error_tor)
                            network -> getString(R.string.onboarding_error_network)
                            else -> getString(R.string.ffi_error)
                        },
                    )
                    openOrbot.visibility = if (network && viaTor) View.VISIBLE else View.GONE
                }
        }
    }

    /**
     * Возвращение аккаунта из копии: база открывается под новым PIN,
     * дальше — экран копии в режиме возвращения аккаунта.
     *
     * 🔐 PIN не передаётся дальше: база открыта здесь, и экран копии
     * работает с уже открытым хранилищем. Не дошедшее до конца
     * возвращение стирает базу — см. [RestoreActivity].
     */
    private fun startRecovery() {
        if (!pin.isComplete) {
            showError(getString(R.string.onboarding_error_pin))

            return
        }

        val pinValue = pin.take()

        if (!Pin.isAcceptable(pinValue)) {
            showError(getString(R.string.onboarding_error_pin))

            return
        }

        val viaTor = !direct.isChecked

        setWorking(true)

        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.unlock(this@OnboardingActivity, pinValue)

                    if (!viaTor) {
                        messenger.setProxy(FfiProxy.Direct)
                        NetworkProxy.apply(FfiProxy.Direct)
                    }
                }.onFailure { AccountWipe.wipe(this@OnboardingActivity) }
            }

            setWorking(false)

            opened
                .onSuccess {
                    startActivity(
                        Intent(this@OnboardingActivity, RestoreActivity::class.java)
                            .putExtra(RestoreActivity.EXTRA_RECOVER_ACCOUNT, true),
                    )
                    finish()
                }
                .onFailure { showError(getString(R.string.ffi_error)) }
        }
    }

    private fun setWorking(working: Boolean) {
        // Кнопка блокируется на время подбора proof-of-work: повторное
        // нажатие запустило бы вторую регистрацию поверх первой.
        createButton.isEnabled = !working
        username.isEnabled = !working
        direct.isEnabled = !working
        pin.setEnabled(!working)

        val visibility = if (working) View.VISIBLE else View.GONE
        progress.visibility = visibility
        progressLabel.visibility = visibility

        if (working) {
            error.visibility = View.INVISIBLE
            openOrbot.visibility = View.GONE
        }
    }

    /**
     * Открывает Orbot, а если его нет — его страницу в магазине.
     *
     * Запуск по имени пакета не требует объявлять Orbot в манифесте:
     * видимость пакетов ограничивает запросы к списку приложений,
     * а не запуск.
     */
    private fun launchOrbot() {
        val launch = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(ORBOT_PACKAGE)
        val store = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$ORBOT_PACKAGE"))

        for (intent in listOf(launch, store)) {
            try {
                startActivity(intent)
                return
            } catch (_: ActivityNotFoundException) {
                // Следующий вариант.
            }
        }

        showError(getString(R.string.onboarding_orbot_missing))
    }

    private fun showError(message: String) {
        error.text = message
        error.visibility = View.VISIBLE
    }

    /**
     * Адрес сервера.
     *
     * Пока задан константой сборки: настройка адреса появится вместе
     * с экраном выбора сервера. Значение вынесено в BuildConfig, чтобы
     * отладочная и релизная сборки не могли случайно указать на один
     * и тот же сервер.
     */
    private fun serverUrl(): String = BuildConfig.AEGIS_SERVER_URL

    companion object {
        /** Идентификатор устройства для последующих запросов. */
        const val EXTRA_DEVICE_ID = "device_id"

        /** Пакет Orbot. */
        private const val ORBOT_PACKAGE = "org.torproject.android"

        /**
         * Минимальная длина PIN.
         *
         * Совпадает с проверкой в ядре: шесть символов вместе
         * с растягиванием Argon2id делают перебор изъятого устройства
         * делом лет, а не часов.
         */

        /** Размер ключа SQLCipher. */
        private const val DATABASE_KEY_SIZE = 32
    }
}

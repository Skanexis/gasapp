// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppTextField
import org.gasapp.app.components.PinPad
import org.gasapp.app.core.AccountWipe
import org.gasapp.app.core.Core
import org.gasapp.app.core.Pin
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.net.EmbeddedTor
import org.gasapp.app.net.NetworkProxy
import org.gasapp.app.core.TouchTarget
import uniffi.gasapp.FfiAccount
import uniffi.gasapp.FfiException
import uniffi.gasapp.FfiProxy
import uniffi.gasapp.Messenger
import uniffi.gasapp.canonicalUsername
import uniffi.gasapp.validateTorBridges

/**
 * Онбординг: регистрация первого аккаунта — по шагам.
 *
 * Приветствие → имя и почта (и сеть) → PIN → код из письма.
 * Возвращение из копии идёт с приветствия сразу к PIN: имя придёт из
 * копии, а почта для него не нужна. Шаги — страницы одного экрана:
 * PIN, Tor и мосты общие для обоих путей.
 *
 * # Почему код — после PIN
 *
 * Письмо с кодом просит сервер, а в сеть приложение выходит только
 * через ядро, которому нужна открытая база. Поэтому база создаётся
 * на шаге PIN, и уже из неё уходит запрос письма. Пока человек ходит
 * за кодом, приложение может заблокироваться: имя и адрес лежат
 * в зашифрованной базе (`pendingRegistration`), и экран входа
 * возвращает сюда же, на шаг кода.
 *
 * 🔐 Предупреждение об отсутствии аудита показывается на первом шаге,
 * **до** любой кнопки, и тем же кеглем, что и остальной текст (раздел 21
 * плана). Мессенджер, обещающий защиту, которую не проверял никто
 * посторонний, обязан сказать об этом до того, как пользователь начнёт
 * ему доверять.
 */
class OnboardingActivity : AppCompatActivity() {

    private lateinit var username: GasAppTextField
    private lateinit var usernameHelper: TextView
    private lateinit var email: GasAppTextField
    private lateinit var emailHelper: TextView
    private lateinit var code: GasAppTextField
    private lateinit var codeHelper: TextView
    private lateinit var confirmButton: GasAppButton
    private lateinit var resendButton: GasAppButton

    /** Когда можно просить письмо снова, по часам устройства. */
    private var resendAllowedAt = 0L

    /** Отсчёт на кнопке повторной отправки. */
    private var resendWatch: kotlinx.coroutines.Job? = null
    private lateinit var scroll: ScrollView
    private lateinit var pin: PinPad
    private lateinit var error: TextView
    private lateinit var progressLabel: TextView
    private lateinit var createButton: GasAppButton
    private lateinit var tor: SwitchCompat
    private lateinit var addBridge: GasAppButton
    private lateinit var progressRow: View

    /** Текущий шаг. */
    private var step = Step.Welcome

    /** Путь: новый аккаунт или возвращение из копии. */
    private var restoring = false

    /** «Назад» с шага возвращает на предыдущий, а не закрывает экран. */
    private val stepBack = object : OnBackPressedCallback(false) {
        override fun handleOnBackPressed() = previousStep()
    }

    /** Мосты, введённые на этом экране; сохраняются в базу при её создании. */
    private var bridgesText: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_onboarding)

        // 🔐 До регистрации: поддельной копии не отдают ни имени, ни PIN.
        org.gasapp.app.core.TamperGuard.warnIfForged(this)

        username = findViewById(R.id.onboarding_username)
        usernameHelper = findViewById(R.id.onboarding_username_helper)
        scroll = findViewById(R.id.onboarding_scroll)

        email = findViewById(R.id.onboarding_email)
        emailHelper = findViewById(R.id.onboarding_email_helper)
        code = findViewById(R.id.onboarding_code)
        codeHelper = findViewById(R.id.onboarding_code_helper)
        confirmButton = findViewById(R.id.onboarding_confirm)
        resendButton = findViewById(R.id.onboarding_resend)

        // Исправление имени снимает ошибку: подсказка возвращается.
        username.doAfterTextChanged { clearUsernameError() }
        email.doAfterTextChanged { clearEmailError() }
        findViewById<View>(R.id.onboarding_legal).setOnClickListener {
            org.gasapp.app.core.Legal.show(
                this,
                listOf(
                    org.gasapp.app.core.Legal.Page.Terms,
                    org.gasapp.app.core.Legal.Page.Privacy,
                    org.gasapp.app.core.Legal.Page.Guidelines,
                ),
            )
        }
        code.doAfterTextChanged { clearCodeError() }
        // 🔐 PIN — своей клавиатурой, не системной (см. [PinPad]).
        pin = PinPad(findViewById(android.R.id.content))
        error = findViewById(R.id.onboarding_error)
        progressLabel = findViewById(R.id.onboarding_progress_label)
        progressRow = findViewById(R.id.onboarding_progress_row)

        showMascotIfProvided()
        createButton = findViewById(R.id.onboarding_create)

        tor = findViewById(R.id.onboarding_tor)
        addBridge = findViewById(R.id.onboarding_add_bridge)
        addBridge.setOnClickListener { promptBridges() }

        createButton.setOnClickListener { if (restoring) startRecovery() else openAndSendCode() }
        confirmButton.setOnClickListener { confirmCode() }
        resendButton.setOnClickListener { resendCode() }
        TouchTarget.expand(resendButton)

        findViewById<GasAppButton>(R.id.onboarding_start).setOnClickListener {
            restoring = false
            showStep(Step.Username)
        }
        findViewById<GasAppButton>(R.id.onboarding_recover).setOnClickListener {
            restoring = true
            showStep(Step.Pin)
        }
        findViewById<GasAppButton>(R.id.onboarding_next).setOnClickListener { usernameDone() }
        findViewById<View>(R.id.onboarding_back).setOnClickListener { previousStep() }

        // «Далее» на клавиатуре — тот же шаг вперёд, что и кнопка;
        // Enter подключённой клавиатуры приходит нажатием клавиши.
        username.setOnEditorActionListener { _, action, event ->
            val enter = event?.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN
            (action == EditorInfo.IME_ACTION_NEXT || enter).also { if (it) email.requestFocus() }
        }
        email.setOnEditorActionListener { _, action, event ->
            val enter = event?.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN
            (action == EditorInfo.IME_ACTION_NEXT || enter).also { if (it) usernameDone() }
        }
        code.setOnEditorActionListener { _, action, event ->
            val enter = event?.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN
            (action == EditorInfo.IME_ACTION_DONE || enter).also { if (it) confirmCode() }
        }

        onBackPressedDispatcher.addCallback(this, stepBack)

        savedInstanceState?.let {
            restoring = it.getBoolean(STATE_RESTORING)
            step = Step.entries[it.getInt(STATE_STEP)]
        }

        // Регистрация не закончена: база открыта, имя и адрес в ней —
        // человек вернулся с кодом из письма (см. описание класса).
        pendingRegistration()?.let { pending ->
            restoring = false
            username.setText(pending.username)
            email.setText(pending.email)
            step = Step.Code
        }

        // Шаг кода без открытой базы невозможен: экран пересоздан
        // после блокировки. Назад к началу — вход вернёт сюда сам.
        if (step == Step.Code && !Core.isUnlocked) step = Step.Welcome

        showStep(step)

        tor.setOnCheckedChangeListener { _, checked ->
            findViewById<TextView>(R.id.onboarding_network_hint)
                .setText(if (checked) R.string.onboarding_network_tor else R.string.onboarding_network_direct)
            // Tor включили — прогрев; выключили — он не нужен.
            if (checked) {
                prewarmTor()
            } else {
                lifecycleScope.launch(Dispatchers.IO) { EmbeddedTor.stop() }
                addBridge.visibility = View.GONE
            }
        }

        // Умолчание регистрации — прямое соединение; Tor человек включает
        // сам. Прогрев — только если он уже включён (экран пересоздан):
        // Tor подключается, пока человек вводит имя и PIN.
        if (tor.isChecked) prewarmTor()
        watchTorForBlocking()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(STATE_STEP, step.ordinal)
        outState.putBoolean(STATE_RESTORING, restoring)
    }

    /**
     * Показывает шаг: его страницу, его кнопку и ход в шапке.
     *
     * 🔐 PIN не переживает ухода с шага: набранные цифры стираются,
     * а не ждут в памяти, пока человек вернётся.
     */
    private fun showStep(target: Step) {
        if (target != Step.Pin) pin.clear()

        step = target
        error.visibility = View.GONE

        findViewById<View>(R.id.onboarding_page_welcome).isVisible = target == Step.Welcome
        findViewById<View>(R.id.onboarding_page_username).isVisible = target == Step.Username
        findViewById<View>(R.id.onboarding_page_pin).isVisible = target == Step.Pin
        findViewById<View>(R.id.onboarding_page_code).isVisible = target == Step.Code

        findViewById<View>(R.id.onboarding_start).isVisible = target == Step.Welcome
        findViewById<View>(R.id.onboarding_recover).isVisible = target == Step.Welcome
        findViewById<View>(R.id.onboarding_next).isVisible = target == Step.Username
        createButton.isVisible = target == Step.Pin
        confirmButton.isVisible = target == Step.Code

        findViewById<View>(R.id.onboarding_bar).isVisible = target != Step.Welcome
        stepBack.isEnabled = target != Step.Welcome

        // Возвращение из копии — один шаг: полоска хода ему не нужна.
        val current = when (target) {
            Step.Code -> 3
            Step.Pin -> 2
            else -> 1
        }
        findViewById<View>(R.id.onboarding_steps).visibility = if (restoring) View.INVISIBLE else View.VISIBLE
        findViewById<TextView>(R.id.onboarding_step_label).apply {
            isVisible = !restoring
            text = getString(R.string.onboarding_step, current, STEPS)
            contentDescription = getString(R.string.onboarding_step_description, current, STEPS)
        }
        findViewById<View>(R.id.onboarding_step_2).setBackgroundResource(
            if (current >= 2) R.drawable.bg_step_segment_active else R.drawable.bg_step_segment,
        )
        findViewById<View>(R.id.onboarding_step_3).apply {
            // Возвращение из копии кода не требует: третьего шага у него нет.
            isVisible = !restoring
            setBackgroundResource(
                if (current >= 3) R.drawable.bg_step_segment_active else R.drawable.bg_step_segment,
            )
        }
        findViewById<View>(R.id.onboarding_step_1).setBackgroundResource(R.drawable.bg_step_segment_active)

        findViewById<TextView>(R.id.onboarding_pin_title).setText(
            if (restoring) R.string.onboarding_restore_pin_title else R.string.onboarding_pin_title,
        )
        createButton.setText(if (restoring) R.string.onboarding_restore_continue else R.string.onboarding_create)

        placeNetwork(if (restoring) R.id.onboarding_page_pin else R.id.onboarding_page_username)
        scroll.scrollTo(0, 0)

        val keyboard = getSystemService(InputMethodManager::class.java)
        when (target) {
            Step.Username -> {
                username.requestFocus()
                username.post { keyboard?.showSoftInput(username, 0) }
            }
            Step.Code -> {
                findViewById<TextView>(R.id.onboarding_code_subtitle).text =
                    getString(R.string.onboarding_code_subtitle, email.text?.toString().orEmpty().trim())
                code.requestFocus()
                code.post { keyboard?.showSoftInput(code, 0) }
                watchResend()
            }
            else -> {
                keyboard?.hideSoftInputFromWindow(username.windowToken, 0)
                username.clearFocus()
            }
        }
    }

    /**
     * Показывает персонажа на приветствии, если владелец положил его
     * картинку в ресурсы (`art_mascot`, см. design/art/README.md).
     *
     * Ресурс ищется по имени: пока картинки нет, сборка не ломается,
     * а сцена остаётся с одним логотипом.
     */
    private fun showMascotIfProvided() {
        @Suppress("DiscouragedApi")
        val art = resources.getIdentifier("art_mascot", "drawable", packageName)
        if (art == 0) return

        findViewById<android.widget.ImageView>(R.id.onboarding_mascot).apply {
            setImageResource(art)
            visibility = View.VISIBLE
        }
        // Логотип уступает персонажу середину сцены.
        findViewById<View>(R.id.onboarding_wordmark).apply {
            (layoutParams as android.widget.FrameLayout.LayoutParams).gravity =
                android.view.Gravity.TOP or android.view.Gravity.CENTER_HORIZONTAL
            translationY = resources.getDimension(R.dimen.space_l)
            requestLayout()
        }
    }

    /** Незавершённая регистрация из открытой базы, если она есть. */
    private fun pendingRegistration(): uniffi.gasapp.FfiPendingRegistration? =
        if (Core.isUnlocked) {
            runCatching {
                Core.messenger().takeIf { it.ownUsername() == null }?.pendingRegistration()
            }.getOrNull()
        } else {
            null
        }

    /** Переносит блок сети на страницу [pageId] — в её конец. */
    private fun placeNetwork(pageId: Int) {
        val network = findViewById<View>(R.id.onboarding_network)
        val page = findViewById<ViewGroup>(pageId)
        if (network.parent === page) return

        (network.parent as ViewGroup).removeView(network)
        page.addView(network)
    }

    private fun previousStep() {
        // Во время регистрации шаг не меняется: работа уже идёт.
        if (createButton.isLoading || confirmButton.isLoading) return

        when (step) {
            Step.Welcome -> Unit
            Step.Username -> {
                // База уже создана под PIN, а человек уходит в начало:
                // регистрация отменена, и незарегистрированная база
                // стирается — иначе следующий запуск принял бы её за аккаунт.
                if (pendingRegistration() != null) {
                    lifecycleScope.launch(Dispatchers.IO) { AccountWipe.wipe(this@OnboardingActivity) }
                }
                showStep(Step.Welcome)
            }
            Step.Pin -> showStep(if (restoring) Step.Welcome else Step.Username)
            Step.Code -> showStep(Step.Username)
        }
    }

    /**
     * Шаг имени и почты пройден, если оба годятся.
     *
     * Дальше — PIN. Если база уже открыта (человек вернулся с шага кода
     * поправить имя или адрес), PIN второй раз не спрашивается: письмо
     * уходит заново только при смене адреса.
     */
    private fun usernameDone() {
        val name = canonicalName() ?: return
        val address = emailAddress() ?: return

        if (!Core.isUnlocked) {
            showStep(Step.Pin)
            return
        }

        val pending = pendingRegistration()
        if (pending?.email == address) {
            // Тот же адрес — тот же код: он не сгорает от занятого имени.
            runCatching { Core.messenger().setPendingRegistration(name, address) }
            showStep(Step.Code)
        } else {
            sendCodeFromOpenBase(name, address)
        }
    }

    /**
     * Адрес почты или `null` с ошибкой под полем.
     *
     * Проверка здесь грубая — чтобы не ходить в сеть с опечаткой;
     * правило адреса — ядра (`requestEmailCode` отвергнет негодный).
     */
    private fun emailAddress(): String? {
        val raw = email.text?.toString().orEmpty().trim().lowercase()

        if (!android.util.Patterns.EMAIL_ADDRESS.matcher(raw).matches() || raw.any { it.code > 127 }) {
            showEmailError(R.string.onboarding_error_email)
            return null
        }

        return raw
    }

    /** Просит письмо на новый адрес, когда база уже открыта. */
    private fun sendCodeFromOpenBase(name: String, address: String) {
        val next = findViewById<GasAppButton>(R.id.onboarding_next)
        next.isLoading = true

        lifecycleScope.launch {
            val sent = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()
                    messenger.setPendingRegistration(name, address)
                    requestCodeWithRetry(messenger, address, tor.isChecked)
                }
            }

            next.isLoading = false

            sent
                .onSuccess {
                    startResendCooldown()
                    showStep(Step.Code)
                }
                .onFailure { failure ->
                    if (failure is FfiException.InvalidEmail) {
                        showEmailError(R.string.onboarding_error_email)
                    } else {
                        showEmailError(R.string.onboarding_error_code_send)
                    }
                }
        }
    }

    /**
     * Каноничное имя или `null` с ошибкой под полем.
     *
     * 🔐 Правило имени — ядра, а не экрана: строчные латинские буквы,
     * цифры и `_`. Двойник «аlice» с кириллической «а» здесь
     * отвергается, а «Alice» становится «alice».
     */
    private fun canonicalName(): String? {
        val raw = username.text?.toString().orEmpty()

        return try {
            canonicalUsername(raw)
        } catch (_: FfiException) {
            showUsernameError()
            null
        } catch (_: LinkageError) {
            // Ядро не загрузилось — это не ошибка имени. Регистрация
            // упадёт на том же и сотрёт базу, как при любом сбое.
            raw.trim()
        }
    }

    /**
     * Шаг PIN: создаёт базу под PIN, подключается и просит у сервера
     * письмо с кодом. Аккаунт регистрируется позже — на шаге кода.
     */
    private fun openAndSendCode() {
        // Имя и адрес проверены на своём шаге; здесь — ещё раз: ошибка
        // ведёт обратно к полю, а не уходит на сервер.
        val name = canonicalName() ?: return showStep(Step.Username)
        val address = emailAddress() ?: return showStep(Step.Username)

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
            pinValue.fill(0)
            showError(getString(R.string.onboarding_error_pin))

            return
        }

        // 🔐 Такие PIN перебирают первыми (см. [Pin.isTooSimple]).
        if (Pin.isTooSimple(pinValue)) {
            pinValue.fill(0)
            showError(getString(R.string.onboarding_error_pin_simple))

            return
        }

        // 🔐 Выбор сети берётся один раз, до работы: переключатель
        // на время регистрации заблокирован.
        val viaTor = tor.isChecked

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
                    // Мосты с этого экрана — в новую базу до применения
                    // режима сети (см. EmbeddedTor.pendingBridges).
                    if (viaTor) EmbeddedTor.setPendingBridges(bridgesText)

                    stage(Stage.KEYS)
                    // 🔐 PIN байтами обнуляется сразу после вывода ключа.
                    val messenger = try {
                        Core.unlock(this@OnboardingActivity, pinValue)
                    } finally {
                        pinValue.fill(0)
                    }

                    // 🔐 Ядро без настройки выбирает Tor (отказ в
                    // безопасную сторону), поэтому выбор человека
                    // записывается явно и до первого запроса:
                    // регистрация — первое, что видит сервер.
                    if (!viaTor) {
                        messenger.setProxy(FfiProxy.Direct)
                        NetworkProxy.apply(this@OnboardingActivity, FfiProxy.Direct)
                    } else {
                        stage(Stage.TOR)
                        awaitTor()
                    }

                    stage(Stage.REGISTER)
                    // Имя и адрес — в зашифрованную базу: с ними человек
                    // вернётся к шагу кода, даже если приложение
                    // заблокируется, пока он читает почту.
                    messenger.setPendingRegistration(name, address)
                    requestCodeWithRetry(messenger, address, viaTor)
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
                    // Сюда приходят сбои открытия базы и запроса письма.
                    AccountWipe.wipe(this@OnboardingActivity)
                }
            }

            setWorking(false)

            result
                .onSuccess {
                    // Письмо ушло: дальше — код из него.
                    startResendCooldown()
                    showStep(Step.Code)
                }
                .onFailure { failure ->
                    // Текст ошибки ядра намеренно неинформативен, поэтому
                    // показывается собственная строка. Различать причины
                    // здесь можно только по типу исключения.
                    //
                    // 🔐 Через Tor сбой сети — чаще всего не готовая сеть
                    // Tor. Напрямую приложение само не уходит: человек
                    // либо повторяет, либо явно выбирает прямое
                    // соединение.
                    if (failure is FfiException.InvalidEmail) {
                        showStep(Step.Username)
                        showEmailError(R.string.onboarding_error_email)

                        return@onFailure
                    }

                    val network = failure is FfiException || failure is TorNotReady

                    showError(
                        when {
                            network && viaTor -> getString(R.string.onboarding_error_tor)
                            network -> getString(R.string.onboarding_error_network)
                            else -> getString(R.string.ffi_error)
                        },
                    )
                }
        }
    }

    /**
     * Шаг кода: регистрирует аккаунт с кодом из письма.
     *
     * 🔐 Сбой здесь базу не стирает: она открыта под PIN, который
     * человек уже задал, а код можно ввести заново или запросить новый.
     */
    private fun confirmCode() {
        val name = canonicalName() ?: return showStep(Step.Username)
        val address = emailAddress() ?: return showStep(Step.Username)
        val digits = code.text?.toString().orEmpty().trim()

        if (digits.length != CODE_LENGTH) {
            showCodeError(R.string.onboarding_error_code_length)
            return
        }

        val viaTor = tor.isChecked

        confirmButton.isLoading = true
        code.isEnabled = false
        resendButton.isEnabled = false

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    registerWithRetry(Core.messenger(), name, address, digits, viaTor)
                        .also { Core.maintainPrekeysNow() }
                }
            }

            confirmButton.isLoading = false
            code.isEnabled = true
            resendButton.isEnabled = true

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
                    when (failure) {
                        // Код не тот, истёк или сгорел после пяти неверных
                        // вводов — сервер этого не различает, и экран тоже.
                        is FfiException.EmailCodeRejected -> showCodeError(R.string.onboarding_error_code)
                        // Имя занято — не сбой сети: назад к полю имени.
                        // Код остаётся в силе: письмо второй раз не нужно.
                        is FfiException.UsernameTaken -> {
                            showStep(Step.Username)
                            showUsernameError(R.string.onboarding_error_taken)
                        }
                        is FfiException.EmailTaken -> {
                            showStep(Step.Username)
                            showEmailError(R.string.onboarding_error_email_taken)
                        }
                        is FfiException.InvalidEmail -> {
                            showStep(Step.Username)
                            showEmailError(R.string.onboarding_error_email)
                        }
                        else -> showCodeError(
                            if (viaTor) R.string.onboarding_error_tor else R.string.onboarding_error_network,
                        )
                    }
                }
        }
    }

    /** Просит письмо ещё раз — не чаще раза в минуту (так решает сервер). */
    private fun resendCode() {
        if (System.currentTimeMillis() < resendAllowedAt) return

        val address = emailAddress() ?: return showStep(Step.Username)
        val viaTor = tor.isChecked

        resendButton.isLoading = true

        lifecycleScope.launch {
            val sent = withContext(Dispatchers.IO) {
                runCatching { requestCodeWithRetry(Core.messenger(), address, viaTor) }
            }

            resendButton.isLoading = false

            sent
                .onSuccess {
                    startResendCooldown()
                    clearCodeError()
                    codeHelper.setText(R.string.onboarding_code_resent)
                }
                .onFailure { showCodeError(R.string.onboarding_error_code_send) }
        }
    }

    private fun startResendCooldown() {
        resendAllowedAt = System.currentTimeMillis() + RESEND_COOLDOWN_MS
    }

    /** Ведёт обратный отсчёт на кнопке повторной отправки. */
    private fun watchResend() {
        // Один отсчёт на экран: повторный показ шага не заводит второй.
        resendWatch?.cancel()
        resendWatch = lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (step == Step.Code) {
                    val left = resendAllowedAt - System.currentTimeMillis()

                    if (!resendButton.isLoading) {
                        resendButton.isEnabled = left <= 0 && !confirmButton.isLoading
                        resendButton.text = if (left > 0) {
                            getString(R.string.onboarding_code_resend_in, (left + 999) / 1000)
                        } else {
                            getString(R.string.onboarding_code_resend)
                        }
                    }
                    delay(RESEND_TICK_MS)
                }
            }
        }
    }

    /**
     * Просит письмо с кодом; через Tor при сбое сети повторяет в течение
     * [REGISTER_RETRY_WINDOW_MS] — по той же причине, что и регистрация.
     */
    private suspend fun requestCodeWithRetry(messenger: Messenger, address: String, viaTor: Boolean) {
        val deadline = System.currentTimeMillis() + REGISTER_RETRY_WINDOW_MS

        while (true) {
            try {
                return messenger.requestEmailCode(address)
            } catch (failure: FfiException.Core) {
                if (!viaTor || System.currentTimeMillis() >= deadline) throw failure
                delay(REGISTER_RETRY_MS)
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
            pinValue.fill(0)
            showError(getString(R.string.onboarding_error_pin))

            return
        }

        // 🔐 Такие PIN перебирают первыми (см. [Pin.isTooSimple]).
        if (Pin.isTooSimple(pinValue)) {
            pinValue.fill(0)
            showError(getString(R.string.onboarding_error_pin_simple))

            return
        }

        val viaTor = tor.isChecked

        setWorking(true)

        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching {
                    if (viaTor) EmbeddedTor.setPendingBridges(bridgesText)

                    stage(Stage.KEYS)
                    // 🔐 PIN байтами обнуляется сразу после вывода ключа.
                    val messenger = try {
                        Core.unlock(this@OnboardingActivity, pinValue)
                    } finally {
                        pinValue.fill(0)
                    }

                    if (!viaTor) {
                        messenger.setProxy(FfiProxy.Direct)
                        NetworkProxy.apply(this@OnboardingActivity, FfiProxy.Direct)
                    } else {
                        stage(Stage.TOR)
                        awaitTor()
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
                .onFailure { failure ->
                    showError(
                        getString(if (failure is TorNotReady) R.string.onboarding_error_tor else R.string.ffi_error),
                    )
                }
        }
    }

    /**
     * Регистрирует имя; через Tor при сбое сети повторяет в течение
     * [REGISTER_RETRY_WINDOW_MS].
     *
     * Сразу после подключения к сети Tor (особенно через мосты) Arti ещё
     * докачивает каталог, и встреча с onion-сервисом сервера первые
     * секунды отказывает сразу («нет цепочки для точки встречи»), а
     * потом проходит. Повтор безопасен: до ответа сервера ядро ничего
     * не сохраняет, identity создаётся заново.
     */
    private suspend fun registerWithRetry(
        messenger: Messenger,
        name: String,
        address: String,
        digits: String,
        viaTor: Boolean,
    ): FfiAccount {
        val deadline = System.currentTimeMillis() + REGISTER_RETRY_WINDOW_MS

        while (true) {
            try {
                return messenger.register(name, address, digits, System.currentTimeMillis())
            } catch (failure: FfiException.Core) {
                if (!viaTor || System.currentTimeMillis() >= deadline) throw failure
                delay(REGISTER_RETRY_MS)
            }
        }
    }

    /**
     * Ждёт подключения встроенного Tor, показывая ход в подписи.
     *
     * Первый запуск качает каталог сети Tor — от нескольких секунд до
     * минуты. Без ожидания регистрация упёрлась бы в таймаут соединения.
     *
     * @throws TorNotReady Tor не подключился за отведённое время.
     */
    private suspend fun awaitTor() {
        val ready = EmbeddedTor.awaitReady(TOR_WAIT_MS) { status ->
            withContext(Dispatchers.Main) {
                if (EmbeddedTor.needsUserBridges(this@OnboardingActivity)) addBridge.visibility = View.VISIBLE
                progressLabel.text = getString(
                    when {
                        status.bridges -> R.string.tor_status_via_bridges
                        status.stalled -> R.string.tor_status_stalled
                        else -> R.string.tor_status_connecting
                    },
                    status.percent.toInt(),
                )
            }
        }

        withContext(Dispatchers.Main) { progressLabel.setText(R.string.onboarding_working) }

        if (!ready) throw TorNotReady()
    }

    /** Встроенный Tor не подключился вовремя. */
    private class TorNotReady : Exception()

    /** Запускает Tor заранее — с мостами, если их уже ввели. */
    private fun prewarmTor() {
        val lines = bridgesLines()

        lifecycleScope.launch(Dispatchers.IO) { EmbeddedTor.ensureStarted(this@OnboardingActivity, lines) }
    }

    private fun bridgesLines(): List<String> =
        bridgesText?.lines()?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()

    /** Показывает «Добавить мост», когда Tor похоже заблокирован. */
    private fun watchTorForBlocking() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {

                while (true) {
                    if (tor.isChecked && EmbeddedTor.needsUserBridges(this@OnboardingActivity)) {
                        addBridge.visibility = View.VISIBLE
                    }
                    delay(TOR_WATCH_MS)
                }
            }
        }
    }

    /**
     * Диалог ввода мостов. Проверка — та же, что в ядре; годные мосты
     * сразу перезапускают Tor и сохраняются в базу при её создании.
     */
    private fun promptBridges() {
        val field = GasAppTextField(this).apply {
            setText(bridgesText.orEmpty())
            hint = getString(R.string.network_bridges_hint)
            minLines = 3
            gravity = android.view.Gravity.TOP or android.view.Gravity.START
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 12f
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }

        GasAppDialog(this)
            .title(R.string.onboarding_bridges_title)
            .message(R.string.network_bridges_help)
            .content(field)
            .secondary()
            .primary(R.string.network_save, closeOnClick = false) { dialog ->
                val text = field.text.toString()

                // Ошибка — в самом диалоге: набранные мосты остаются
                // на месте, и опечатку можно поправить.
                if (!validateTorBridges(text)) {
                    field.hasError = true
                    dialog.showError(R.string.network_bridges_invalid)
                    return@primary
                }

                dialog.dismiss()
                bridgesText = text.takeIf { it.isNotBlank() }
                error.visibility = View.GONE
                prewarmTor()
            }
            .show()
    }

    /** Этапы хода регистрации — по порядку, как они идут на деле. */
    private enum class Stage(val row: Int, val dot: Int, val spinner: Int, val done: Int, val label: Int) {
        KEYS(R.id.onboarding_stage_1, R.id.onboarding_stage_1_dot, R.id.onboarding_stage_1_spinner, R.id.onboarding_stage_1_done, R.id.onboarding_stage_1_label),
        TOR(R.id.onboarding_stage_2, R.id.onboarding_stage_2_dot, R.id.onboarding_stage_2_spinner, R.id.onboarding_stage_2_done, R.id.onboarding_stage_2_label),
        REGISTER(R.id.onboarding_stage_3, R.id.onboarding_stage_3_dot, R.id.onboarding_stage_3_spinner, R.id.onboarding_stage_3_done, R.id.onboarding_stage_3_label),
    }

    /**
     * Отмечает этап [current] текущим, прежние — пройденными.
     *
     * Зовётся из фонового потока: переключение — на главном.
     */
    private suspend fun stage(current: Stage) = withContext(Dispatchers.Main) {
        for (step in Stage.entries) {
            val state = step.ordinal.compareTo(current.ordinal)
            findViewById<View>(step.dot).visibility = if (state > 0) View.VISIBLE else View.GONE
            findViewById<View>(step.spinner).visibility = if (state == 0) View.VISIBLE else View.GONE
            findViewById<View>(step.done).visibility = if (state < 0) View.VISIBLE else View.GONE
            findViewById<TextView>(step.label).setTextColor(
                getColor(if (state == 0) R.color.text_primary else R.color.text_tertiary),
            )
        }
    }

    /**
     * Все этапы — впереди; этап Tor и регистрации виден, только если
     * он будет: прямое соединение Tor не ждёт, восстановление имя не
     * регистрирует.
     */
    private fun resetStages() {
        for (step in Stage.entries) {
            findViewById<View>(step.dot).visibility = View.VISIBLE
            findViewById<View>(step.spinner).visibility = View.GONE
            findViewById<View>(step.done).visibility = View.GONE
            findViewById<TextView>(step.label).setTextColor(getColor(R.color.text_tertiary))
        }
        findViewById<View>(Stage.TOR.row).visibility = if (tor.isChecked) View.VISIBLE else View.GONE
        findViewById<View>(Stage.REGISTER.row).visibility = if (restoring) View.GONE else View.VISIBLE
    }

    private fun setWorking(working: Boolean) {
        // Кнопка блокируется на время подбора proof-of-work: повторное
        // нажатие запустило бы вторую регистрацию поверх первой.
        createButton.isLoading = working
        username.isEnabled = !working
        email.isEnabled = !working
        tor.isEnabled = !working
        pin.setEnabled(!working)

        progressRow.visibility = if (working) View.VISIBLE else View.GONE
        if (working) resetStages()

        if (working) {
            error.visibility = View.GONE
            // Ход подключения Tor и подбора proof-of-work — под
            // клавиатурой: без прокрутки человек видел бы только
            // погасшую кнопку.
            revealBelow(progressRow)
        }
    }

    /**
     * Показывает ошибку и прокручивает к ней.
     *
     * Ошибка стоит под формой, а форма длиннее экрана: прежде она
     * появлялась за нижним краем, и человек видел только сброшенный
     * PIN — без объяснения, что пошло не так.
     */
    private fun showError(message: String) {
        error.text = message
        error.visibility = View.VISIBLE
        revealBelow(error)
    }

    /** Ошибка имени — на месте подсказки под полем (UI kit, Inputs). */
    private fun showUsernameError(@androidx.annotation.StringRes message: Int = R.string.onboarding_error_username) {
        username.hasError = true
        usernameHelper.setText(message)
        usernameHelper.setTextColor(getColor(R.color.status_error))
        usernameHelper.setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_alert_small, 0, 0, 0)
        usernameHelper.compoundDrawablesRelative[0]?.setTint(getColor(R.color.status_error))
        username.requestFocus()
    }

    private fun clearUsernameError() {
        if (!username.hasError) return

        username.hasError = false
        usernameHelper.setText(R.string.onboarding_username_helper)
        usernameHelper.setTextColor(getColor(R.color.text_muted))
        usernameHelper.setCompoundDrawablesRelative(null, null, null, null)
    }

    /** Ошибка адреса — на месте подсказки под полем, как у имени. */
    private fun showEmailError(@androidx.annotation.StringRes message: Int) {
        email.hasError = true
        emailHelper.setText(message)
        emailHelper.setTextColor(getColor(R.color.status_error))
        emailHelper.setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_alert_small, 0, 0, 0)
        emailHelper.compoundDrawablesRelative[0]?.setTint(getColor(R.color.status_error))
        email.requestFocus()
    }

    private fun clearEmailError() {
        if (!email.hasError) return

        email.hasError = false
        emailHelper.setText(R.string.onboarding_email_helper)
        emailHelper.setTextColor(getColor(R.color.text_muted))
        emailHelper.setCompoundDrawablesRelative(null, null, null, null)
    }

    /** Ошибка кода — на месте подсказки под полем. */
    private fun showCodeError(@androidx.annotation.StringRes message: Int) {
        code.hasError = true
        codeHelper.setText(message)
        codeHelper.setTextColor(getColor(R.color.status_error))
        codeHelper.setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_alert_small, 0, 0, 0)
        codeHelper.compoundDrawablesRelative[0]?.setTint(getColor(R.color.status_error))
        code.requestFocus()
    }

    private fun clearCodeError() {
        if (!code.hasError) return

        code.hasError = false
        codeHelper.setText(R.string.onboarding_code_helper)
        codeHelper.setTextColor(getColor(R.color.text_muted))
        codeHelper.setCompoundDrawablesRelative(null, null, null, null)
    }

    /** Прокручивает форму так, чтобы [view] был виден целиком. */
    private fun revealBelow(view: View) {
        scroll.post {
            val bottom = view.bottom + resources.getDimensionPixelSize(R.dimen.space_m)
            scroll.smoothScrollTo(0, (bottom - scroll.height).coerceAtLeast(scroll.scrollY))
        }
    }

    /**
     * Адрес сервера.
     *
     * Пока задан константой сборки: настройка адреса появится вместе
     * с экраном выбора сервера. Значение вынесено в BuildConfig, чтобы
     * отладочная и релизная сборки не могли случайно указать на один
     * и тот же сервер.
     */
    private fun serverUrl(): String = BuildConfig.GASAPP_SERVER_URL

    /** Шаги онбординга, по порядку. */
    private enum class Step { Welcome, Username, Pin, Code }

    companion object {
        private const val STATE_STEP = "step"
        private const val STATE_RESTORING = "restoring"

        /** Шагов у нового аккаунта: имя с почтой, PIN и код из письма. */
        private const val STEPS = 3

        /** Цифр в коде из письма. */
        private const val CODE_LENGTH = 6

        /** Пауза между письмами на один адрес — столько держит сервер. */
        private const val RESEND_COOLDOWN_MS = 60_000L

        /** Как часто обновлять отсчёт на кнопке повторной отправки. */
        private const val RESEND_TICK_MS = 500L

        /** Идентификатор устройства для последующих запросов. */
        const val EXTRA_DEVICE_ID = "device_id"

        /**
         * Сколько ждать подключения Tor перед регистрацией.
         *
         * С запасом на всю лестницу там, где Tor блокируют: 45 с прямой
         * попытки, запрос свежих мостов к moat и бутстрап через мост.
         */
        private const val TOR_WAIT_MS = 180_000L

        /** Сколько повторять регистрацию через Tor после сбоя сети. */
        private const val REGISTER_RETRY_WINDOW_MS = 60_000L

        /** Пауза между попытками регистрации. */
        private const val REGISTER_RETRY_MS = 3_000L

        /** Как часто проверять, не заблокирован ли Tor. */
        private const val TOR_WATCH_MS = 2_000L

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

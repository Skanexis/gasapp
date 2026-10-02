// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

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
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisTextField
import org.aegis.app.components.PinPad
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.Core
import org.aegis.app.core.Pin
import org.aegis.app.core.SecureWindow
import org.aegis.app.net.EmbeddedTor
import org.aegis.app.net.NetworkProxy
import uniffi.aegis.FfiAccount
import uniffi.aegis.FfiException
import uniffi.aegis.FfiProxy
import uniffi.aegis.Messenger
import uniffi.aegis.canonicalUsername
import uniffi.aegis.validateTorBridges

/**
 * Онбординг: регистрация первого аккаунта — по шагам.
 *
 * Приветствие → имя (и сеть) → PIN. Возвращение из копии идёт
 * с приветствия сразу к PIN: имя придёт из копии. Шаги — страницы
 * одного экрана: PIN, Tor и мосты общие для обоих путей.
 *
 * 🔐 Предупреждение об отсутствии аудита показывается на первом шаге,
 * **до** любой кнопки, и тем же кеглем, что и остальной текст (раздел 21
 * плана). Мессенджер, обещающий защиту, которую не проверял никто
 * посторонний, обязан сказать об этом до того, как пользователь начнёт
 * ему доверять.
 */
class OnboardingActivity : AppCompatActivity() {

    private lateinit var username: AegisTextField
    private lateinit var usernameHelper: TextView
    private lateinit var scroll: ScrollView
    private lateinit var pin: PinPad
    private lateinit var error: TextView
    private lateinit var progressLabel: TextView
    private lateinit var createButton: AegisButton
    private lateinit var direct: SwitchCompat
    private lateinit var addBridge: AegisButton
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
        org.aegis.app.core.TamperGuard.warnIfForged(this)

        username = findViewById(R.id.onboarding_username)
        usernameHelper = findViewById(R.id.onboarding_username_helper)
        scroll = findViewById(R.id.onboarding_scroll)

        // Исправление имени снимает ошибку: подсказка возвращается.
        username.doAfterTextChanged { clearUsernameError() }
        // 🔐 PIN — своей клавиатурой, не системной (см. [PinPad]).
        pin = PinPad(findViewById(android.R.id.content))
        error = findViewById(R.id.onboarding_error)
        progressLabel = findViewById(R.id.onboarding_progress_label)
        progressRow = findViewById(R.id.onboarding_progress_row)

        // Знак на приветствии «печатается» кольцо за кольцом — один раз,
        // при первом показе; без анимаций — сразу целиком.
        findViewById<org.aegis.app.components.GuillocheView>(R.id.onboarding_seal).apply {
            window = WELCOME_SEAL_WINDOW
            if (savedInstanceState == null) inkTo(rings) else inked = rings
        }
        createButton = findViewById(R.id.onboarding_create)

        direct = findViewById(R.id.onboarding_direct)
        addBridge = findViewById(R.id.onboarding_add_bridge)
        addBridge.setOnClickListener { promptBridges() }

        createButton.setOnClickListener { if (restoring) startRecovery() else register() }

        findViewById<AegisButton>(R.id.onboarding_start).setOnClickListener {
            restoring = false
            showStep(Step.Username)
        }
        findViewById<AegisButton>(R.id.onboarding_recover).setOnClickListener {
            restoring = true
            showStep(Step.Pin)
        }
        findViewById<AegisButton>(R.id.onboarding_next).setOnClickListener { usernameDone() }
        findViewById<View>(R.id.onboarding_back).setOnClickListener { previousStep() }

        // «Далее» на клавиатуре — тот же шаг вперёд, что и кнопка;
        // Enter подключённой клавиатуры приходит нажатием клавиши.
        username.setOnEditorActionListener { _, action, event ->
            val enter = event?.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN
            (action == EditorInfo.IME_ACTION_NEXT || enter).also { if (it) usernameDone() }
        }

        onBackPressedDispatcher.addCallback(this, stepBack)

        savedInstanceState?.let {
            restoring = it.getBoolean(STATE_RESTORING)
            step = Step.entries[it.getInt(STATE_STEP)]
        }
        showStep(step)

        direct.setOnCheckedChangeListener { _, checked ->
            findViewById<TextView>(R.id.onboarding_network_hint).apply {
                setText(if (checked) R.string.onboarding_network_direct else R.string.onboarding_network_tor)
                // Прямое соединение — цена за него жёлтым, а не значком в тексте.
                setTextColor(getColor(if (checked) R.color.status_warn else R.color.text_muted))
            }
            // Прямое соединение — Tor не нужен; снова Tor — прогрев.
            if (checked) {
                lifecycleScope.launch(Dispatchers.IO) { EmbeddedTor.stop() }
                addBridge.visibility = View.GONE
            } else {
                prewarmTor()
            }
        }

        // 🔐 Прогрев: Tor подключается, пока человек вводит имя и PIN.
        // Умолчание регистрации — Tor, так что это та же сеть, в которую
        // приложение пошло бы через минуту.
        prewarmTor()
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

        findViewById<View>(R.id.onboarding_start).isVisible = target == Step.Welcome
        findViewById<View>(R.id.onboarding_recover).isVisible = target == Step.Welcome
        findViewById<View>(R.id.onboarding_next).isVisible = target == Step.Username
        createButton.isVisible = target == Step.Pin

        findViewById<View>(R.id.onboarding_bar).isVisible = target != Step.Welcome
        stepBack.isEnabled = target != Step.Welcome

        // Возвращение из копии — один шаг: полоска хода ему не нужна.
        val current = if (target == Step.Pin) 2 else 1
        findViewById<View>(R.id.onboarding_steps).visibility = if (restoring) View.INVISIBLE else View.VISIBLE
        findViewById<TextView>(R.id.onboarding_step_label).apply {
            isVisible = !restoring
            text = getString(R.string.onboarding_step, current, STEPS)
            contentDescription = getString(R.string.onboarding_step_description, current, STEPS)
        }
        findViewById<View>(R.id.onboarding_step_2).setBackgroundResource(
            if (current == 2) R.drawable.bg_step_segment_active else R.drawable.bg_step_segment,
        )
        findViewById<View>(R.id.onboarding_step_1).setBackgroundResource(R.drawable.bg_step_segment_active)

        findViewById<TextView>(R.id.onboarding_pin_title).setText(
            if (restoring) R.string.onboarding_restore_pin_title else R.string.onboarding_pin_title,
        )
        createButton.setText(if (restoring) R.string.onboarding_restore_continue else R.string.onboarding_create)

        placeNetwork(if (restoring) R.id.onboarding_page_pin else R.id.onboarding_page_username)
        scroll.scrollTo(0, 0)

        val keyboard = getSystemService(InputMethodManager::class.java)
        if (target == Step.Username) {
            username.requestFocus()
            username.post { keyboard?.showSoftInput(username, 0) }
        } else {
            keyboard?.hideSoftInputFromWindow(username.windowToken, 0)
            username.clearFocus()
        }
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
        if (createButton.isLoading) return

        when (step) {
            Step.Welcome -> Unit
            Step.Username -> showStep(Step.Welcome)
            Step.Pin -> showStep(if (restoring) Step.Welcome else Step.Username)
        }
    }

    /** Шаг имени пройден, если имя годится по правилу ядра. */
    private fun usernameDone() {
        if (canonicalName() == null) return

        showStep(Step.Pin)
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

    private fun register() {
        // Имя проверено на своём шаге; здесь — ещё раз: ошибка ведёт
        // обратно к полю, а не регистрирует негодное имя.
        val name = canonicalName() ?: return showStep(Step.Username)

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

                    // 🔐 У новой базы режим по умолчанию — встроенный Tor:
                    // его уже применил Core.unlock. Прямое соединение —
                    // только если человек выбрал его сам, и до первого
                    // запроса: регистрация — первое, что видит сервер.
                    if (!viaTor) {
                        messenger.setProxy(FfiProxy.Direct)
                        NetworkProxy.apply(this@OnboardingActivity, FfiProxy.Direct)
                    } else {
                        stage(Stage.TOR)
                        awaitTor()
                    }

                    stage(Stage.REGISTER)
                    registerWithRetry(messenger, name, viaTor)
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
                    // 🔐 Через Tor сбой сети — чаще всего не готовая сеть
                    // Tor. Напрямую приложение само не уходит: человек
                    // либо повторяет, либо явно выбирает прямое
                    // соединение.
                    // Имя занято — не сбой сети: назад к полю имени, с ошибкой
                    // под ним. Прежде сюда приходило «проверьте интернет»,
                    // и человек повторял регистрацию с тем же именем.
                    if (failure is FfiException.UsernameTaken) {
                        showStep(Step.Username)
                        showUsernameError(R.string.onboarding_error_taken)

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

        val viaTor = !direct.isChecked

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
    private suspend fun registerWithRetry(messenger: Messenger, name: String, viaTor: Boolean): FfiAccount {
        val deadline = System.currentTimeMillis() + REGISTER_RETRY_WINDOW_MS

        while (true) {
            try {
                return messenger.register(name, System.currentTimeMillis())
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
                    if (!direct.isChecked && EmbeddedTor.needsUserBridges(this@OnboardingActivity)) {
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
        val field = AegisTextField(this).apply {
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

        AegisDialog(this)
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
        findViewById<View>(Stage.TOR.row).visibility = if (direct.isChecked) View.GONE else View.VISIBLE
        findViewById<View>(Stage.REGISTER.row).visibility = if (restoring) View.GONE else View.VISIBLE
    }

    private fun setWorking(working: Boolean) {
        // Кнопка блокируется на время подбора proof-of-work: повторное
        // нажатие запустило бы вторую регистрацию поверх первой.
        createButton.isLoading = working
        username.isEnabled = !working
        direct.isEnabled = !working
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
    private fun serverUrl(): String = BuildConfig.AEGIS_SERVER_URL

    /** Шаги онбординга, по порядку. */
    private enum class Step { Welcome, Username, Pin }

    companion object {
        /** Окно розетки приветствия: в нём щит. */
        private const val WELCOME_SEAL_WINDOW = 0.46f

        private const val STATE_STEP = "step"
        private const val STATE_RESTORING = "restoring"

        /** Шагов у нового аккаунта: имя и PIN. */
        private const val STEPS = 2

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

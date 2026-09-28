// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisToast
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.BiometricUnlock
import org.aegis.app.core.Core
import org.aegis.app.core.Pin
import org.aegis.app.core.PinAttempts
import org.aegis.app.core.PinBuffer
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.PinFeedback

/**
 * Экран блокировки.
 *
 * 🔐 PIN здесь **не проверяется и не хранится**. Введённое значение
 * уходит в `aegis-keystore`, где растягивается Argon2id и превращается
 * в ключ, которым расшифровывается хранилище: успех расшифровки и есть
 * проверка. Сравнивать строки в UI означало бы держать PIN в памяти
 * процесса — ровно то, от чего защищает блокировка.
 *
 * 🔐 Клавиатура своя, а не системная. Системная принадлежит другому
 * приложению, которое на Android может быть сторонним и видит каждое
 * нажатие — то есть весь PIN целиком.
 */
class LockActivity : AppCompatActivity() {

    private lateinit var dots: LinearLayout
    private lateinit var error: TextView

    /**
     * Введённые цифры.
     *
     * [PinBuffer], а не `String` или `StringBuilder`: строку затереть
     * нельзя, а `StringBuilder.setLength(0)` оставляет символы в своём
     * массиве — дамп памяти запертого приложения показывал PIN.
     */
    private val entered = PinBuffer()

    /** Обратный отсчёт задержки; `null` — ввод разрешён. */
    private var cooldown: CountDownTimer? = null

    /** Кнопки клавиатуры — их же блокирует задержка. */
    private val keypadIds = intArrayOf(
        R.id.key_0, R.id.key_1, R.id.key_2, R.id.key_3, R.id.key_4,
        R.id.key_5, R.id.key_6, R.id.key_7, R.id.key_8, R.id.key_9,
        R.id.key_delete,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Аккаунта нет — вести на онбординг, а не запрашивать PIN.
        // Экран блокировки без аккаунта не имеет смысла: расшифровывать
        // нечего, и пользователь упёрся бы в запрос, который никогда
        // не проходит.
        if (!hasAccount()) {
            startActivity(Intent(this, OnboardingActivity::class.java))
            finish()

            return
        }

        // 🔐 Запрет скриншотов, превью в списке задач и касаний
        // через накрывающее окно.
        //
        // Без FLAG_SECURE система снимает копию экрана при сворачивании
        // и показывает её в переключателе приложений. Без фильтрации
        // накрытых касаний приложение, рисующее поверх других, могло бы
        // подставить свою клавиатуру поверх этой и собрать PIN.
        SecureWindow.applyAlways(this)

        setContentView(R.layout.activity_lock)

        dots = findViewById(R.id.pin_dots)
        error = findViewById(R.id.pin_error)

        bindKeypad()
        renderDots()

        findViewById<View>(R.id.key_biometric).setOnClickListener { offerBiometricUnlock() }
        findViewById<View>(R.id.lock_forgot).setOnClickListener { confirmForgotPin() }
    }

    /**
     * Забытый PIN: объяснение и стирание с возвратом аккаунта.
     *
     * 🔐 Сбросить PIN нельзя: он — половина ключа базы, и обходного
     * пути, который работал бы для владельца, но не для укравшего
     * телефон, нет. Стирание не даёт укравшему ничего: удалить
     * приложение он может и так, а данные без PIN не расшифровать.
     * Аккаунт возвращается только ключом восстановления.
     */
    private fun confirmForgotPin() {
        AegisDialog(this)
            .title(R.string.lock_forgot_title)
            .message(R.string.lock_forgot_body)
            .secondary()
            .primary(R.string.lock_forgot_erase, AegisDialog.Tone.Danger) {
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) { AccountWipe.wipe(this@LockActivity) }

                    startActivity(
                        Intent(this@LockActivity, OnboardingActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                    )
                    finish()
                }
            }
            .show()
    }

    /** Клавиша отпечатка — только когда вход по отпечатку возможен. */
    private fun renderBiometricKey() {
        val available = !Core.isUnlocked &&
            cooldown == null &&
            BiometricUnlock.isEnabled(this) &&
            BiometricUnlock.availability(this) == BiometricUnlock.Availability.Ready

        findViewById<View>(R.id.key_biometric).visibility = if (available) View.VISIBLE else View.INVISIBLE
    }

    /**
     * 🔐 Задержка восстанавливается при каждом появлении экрана.
     *
     * Без этого перебор сводился бы к «свернуть и открыть заново»:
     * счётчик переживает перезапуск, а отсчёт живёт в объекте экрана
     * и умирает вместе с ним.
     */
    override fun onStart() {
        super.onStart()
        applyCooldown()
        renderBiometricKey()
        offerBiometricUnlock()
    }

    /**
     * 🔐 Предлагает войти по биометрии (MASVS AUTH-2.1).
     *
     * Показывается только если человек её включил: конверт с ключом
     * базы существует. Биометрия — способ не набирать PIN, а не второй
     * способ вывести ключ, и без включения её здесь нет вовсе.
     *
     * # Почему не при задержке
     *
     * ⚠️ Во время задержки после неверных попыток биометрия не
     * предлагается. Иначе перебор PIN обходился бы вообще: подержал
     * палец — вошёл, при том что задержка ровно для того и стоит,
     * чтобы вход стоил времени.
     *
     * # Что происходит при отказе
     *
     * Ничего. Экран PIN уже на месте, и человек вводит код. Отказ
     * биометрии обязан вести к PIN, а не к отдельному сообщению
     * об ошибке: неудавшееся подтверждение — штатный случай, а не сбой.
     */
    private fun offerBiometricUnlock() {
        if (Core.isUnlocked || cooldown != null) {
            return
        }

        if (!BiometricUnlock.isEnabled(this)) {
            return
        }

        if (BiometricUnlock.availability(this) != BiometricUnlock.Availability.Ready) {
            return
        }

        val cipher = BiometricUnlock.cipherForUnlocking(this)

        if (cipher == null) {
            // 🔐 Набор отпечатков на устройстве изменился: система
            // уничтожила ключ, и BiometricUnlock стёр конверт. Прежде
            // клавиша отпечатка оставалась на экране и ничего не делала —
            // человек не знал, почему вход по отпечатку перестал работать.
            if (!BiometricUnlock.isEnabled(this)) {
                renderBiometricKey()
                AegisToast.show(this, R.string.lock_biometric_invalidated, AegisToast.Tone.Warning)
            }

            return
        }

        val prompt = androidx.biometric.BiometricPrompt(
            this,
            androidx.core.content.ContextCompat.getMainExecutor(this),
            object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: androidx.biometric.BiometricPrompt.AuthenticationResult,
                ) {
                    unlockWithBiometrics(result)
                }
            },
        )

        val info = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.lock_biometric_title))
            .setSubtitle(getString(R.string.lock_biometric_subtitle))
            // Запасной путь — PIN этого приложения, а не код устройства:
            // из кода устройства ключ базы не выводится.
            .setNegativeButtonText(getString(R.string.lock_biometric_use_pin))
            .setAllowedAuthenticators(
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG,
            )
            .setConfirmationRequired(false)
            .build()

        prompt.authenticate(
            info,
            androidx.biometric.BiometricPrompt.CryptoObject(cipher),
        )
    }

    /**
     * Открывает хранилище ключом из конверта.
     *
     * 🔐 Ключ живёт ровно до открытия базы и затирается сразу:
     * массив остаётся в куче до сборки мусора, и снятый в этот момент
     * дамп памяти отдал бы ключ базы целиком.
     */
    private fun unlockWithBiometrics(
        result: androidx.biometric.BiometricPrompt.AuthenticationResult,
    ) {
        val key = BiometricUnlock.open(this, result)

        if (key == null) {
            // Конверт повреждён. Молча остаёмся на PIN: человеку
            // здесь нечего делать с этим сообщением.
            BiometricUnlock.disable(this)

            return
        }

        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching { Core.unlockWithKey(this@LockActivity, key) }
            }

            key.fill(0)

            if (opened.isSuccess) {
                PinAttempts.recordSuccess(this@LockActivity)
                startActivity(Intent(this@LockActivity, ChatListActivity::class.java))
                finish()

                return@launch
            }

            // Ключ из конверта не подошёл: база сменила ключ, а конверт
            // остался прежним. Вход по PIN запечатает новый.
            Core.close()
            BiometricUnlock.disable(this@LockActivity)
        }
    }

    /**
     * Заведён ли аккаунт на этом устройстве.
     *
     * Проверяется по наличию файла базы, а не по флагу в настройках:
     * флаг можно потерять при очистке данных, оставив базу, и тогда
     * приложение предложило бы регистрацию поверх существующего
     * аккаунта — то есть потерю переписки.
     */
    private fun hasAccount(): Boolean = java.io.File(filesDir, "aegis.db").exists()

    /**
     * 🔐 Затирает введённое при уходе с экрана.
     *
     * PIN не должен пережить сворачивание приложения даже в буфере.
     */
    override fun onStop() {
        super.onStop()
        clearEntry()

        // Таймер не должен пережить экран: иначе он дорисовывает текст
        // в уже уничтоженные вью.
        cooldown?.cancel()
        cooldown = null
    }

    private fun bindKeypad() {
        val digits = mapOf(
            R.id.key_0 to '0', R.id.key_1 to '1', R.id.key_2 to '2',
            R.id.key_3 to '3', R.id.key_4 to '4', R.id.key_5 to '5',
            R.id.key_6 to '6', R.id.key_7 to '7', R.id.key_8 to '8',
            R.id.key_9 to '9',
        )

        for ((id, digit) in digits) {
            findViewById<TextView>(id).setOnClickListener { append(digit) }
        }

        findViewById<ImageView>(R.id.key_delete).setOnClickListener { removeLast() }
    }

    private fun append(digit: Char) {
        if (!entered.append(digit)) {
            return
        }

        error.visibility = View.INVISIBLE
        renderDots()

        // Проверка запускается сама при наборе полной длины: отдельная
        // кнопка «ОК» здесь лишняя, длина PIN фиксирована.
        if (entered.length == Pin.LENGTH) {
            unlock()
        }
    }

    private fun removeLast() {
        if (entered.length > 0) {
            entered.removeLast()
            renderDots()
        }
    }

    /**
     * Показывает, сколько цифр введено.
     *
     * 🔐 Только количество — сами цифры не отображаются нигде.
     */
    private fun renderDots() {
        for (index in 0 until dots.childCount) {
            val filled = index < entered.length
            dots.getChildAt(index).setBackgroundResource(
                if (filled) R.drawable.bg_pin_dot_filled else R.drawable.bg_pin_dot,
            )
        }
    }

    /**
     * 🔐 Открывает хранилище введённым PIN.
     *
     * # Что здесь было
     *
     * Метод не открывал ничего: он звал `clearEntry()` и переходил
     * к списку чатов. Из этого следовало два разных последствия,
     * и второе хуже первого.
     *
     * Первое — приложение не работало после перезапуска. `Core.open`
     * звали только с экрана регистрации, поэтому при втором запуске
     * `Core.messenger()` бросал «хранилище закрыто» на первом же экране.
     *
     * Второе — экран блокировки был декорацией. Он принимал любые шесть
     * цифр и пропускал дальше. Заметить это по коду экрана было нельзя:
     * он выглядит как настоящий, и комментарий обещал, что проверка
     * появится позже.
     *
     * # Почему нет сравнения PIN
     *
     * Его здесь нет и не будет. PIN растягивается Argon2id в ключ, ключ
     * подаётся SQLCipher: подошёл — база открылась, не подошёл — нет.
     * Отдельная проверка означала бы хранить где-то признак верного
     * PIN, то есть подсказку для перебора (раздел 23.4).
     *
     * Отсюда же и обработка ошибки: отличить «неверный PIN» от «база
     * повреждена» на этом уровне нечем, и оба случая считаются неверным
     * PIN. Обратный выбор — засчитывать сбой открытия за успех —
     * недопустим очевидным образом.
     */
    private fun unlock() {
        // 🔐 Байтами: `take` затирает буфер, копию обнуляем после вывода
        // ключа (см. PinBuffer).
        val pin = entered.take()

        clearEntry()
        setKeypadEnabled(false)

        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching {
                    // Argon2id считается около секунды и обязан идти
                    // в фоновом потоке: на главном это «приложение
                    // не отвечает» при каждом вводе.
                    //
                    // 🔐 Ключ собирает Core.unlock — из PIN и секрета,
                    // не покидающего устройство. Здесь его не строят:
                    // две точки сборки ключа разошлись бы, и вторая
                    // открывала бы базу слабее первой.
                    try {
                        Core.unlock(this@LockActivity, pin)
                    } finally {
                        pin.fill(0)
                    }
                }
            }

            if (opened.isSuccess) {
                PinAttempts.recordSuccess(this@LockActivity)

                setKeypadEnabled(true)
                startActivity(Intent(this@LockActivity, ChatListActivity::class.java))
                finish()

                return@launch
            }

            // 🔐 Полуоткрытого состояния быть не должно: если `open`
            // успел сохранить экземпляр до сбоя, следующий экран получил
            // бы мессенджер с неверным ключом.
            Core.close()

            val failures = PinAttempts.recordFailure(
                this@LockActivity,
                System.currentTimeMillis(),
            )

            // 🔐 Opt-in стирание после десяти неверных PIN (раздел 19.3).
            // Стирает то же, что удаление аккаунта на устройстве, —
            // кроме записи на сервере: для запроса к нему нужен ключ,
            // которого без PIN нет.
            if (PinAttempts.shouldWipe(failures, PinAttempts.wipeEnabled(this@LockActivity))) {
                withContext(Dispatchers.IO) { AccountWipe.wipe(this@LockActivity) }

                startActivity(
                    Intent(this@LockActivity, OnboardingActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                )
                finish()

                return@launch
            }

            showError(failures)
            applyCooldown()
        }
    }

    /**
     * Сообщение о неверном PIN.
     *
     * 🔐 Число оставшихся попыток не показывается, и это не упущение.
     * «Осталось 3» — подсказка тому, кто перебирает: она говорит,
     * сколько ещё можно пробовать без ожидания. Тому, кто помнит свой
     * PIN, это число не нужно, а задержка и так видна.
     */
    private fun showError(failures: Int) {
        error.setText(
            if (PinAttempts.delayMillis(failures) > 0) {
                R.string.lock_error_wait
            } else {
                R.string.lock_error_wrong
            },
        )
        error.visibility = View.VISIBLE
        // Точки краснеют и вздрагивают; по окончании — снова по вводу.
        PinFeedback.wrong(dots) { renderDots() }
    }

    /**
     * Блокирует ввод на время задержки и показывает обратный отсчёт.
     *
     * Отсчёт нужен, чтобы заблокированная клавиатура не выглядела
     * поломкой: без него человек, ошибшийся четыре раза, видит экран,
     * переставший отзываться на нажатия.
     */
    private fun applyCooldown() {
        cooldown?.cancel()
        cooldown = null

        val remaining = PinAttempts.remainingMillis(this, System.currentTimeMillis())

        if (remaining <= 0L) {
            setKeypadEnabled(true)

            return
        }

        setKeypadEnabled(false)

        cooldown = object : CountDownTimer(remaining, COOLDOWN_TICK_MILLIS) {
            override fun onTick(left: Long) {
                error.text = getString(R.string.lock_locked_for, formatLeft(left))
                error.visibility = View.VISIBLE
            }

            override fun onFinish() {
                cooldown = null
                error.visibility = View.INVISIBLE
                setKeypadEnabled(true)
            }
        }.also { it.start() }
    }

    /** Остаток ожидания словами: часы, минуты или секунды. */
    private fun formatLeft(millis: Long): String {
        val seconds = (millis + 999L) / 1000L

        return when {
            seconds >= SECONDS_IN_HOUR -> plural(
                R.plurals.lock_left_hours,
                seconds / SECONDS_IN_HOUR,
            )
            seconds >= SECONDS_IN_MINUTE -> plural(
                R.plurals.lock_left_minutes,
                seconds / SECONDS_IN_MINUTE,
            )
            else -> plural(R.plurals.lock_left_seconds, seconds)
        }
    }

    /**
     * Склоняемая единица времени.
     *
     * Через `plurals`, а не форматированием строки: «через 1 секунд»
     * и «через 2 часов» выглядят как поломка интерфейса, а экран
     * блокировки — первое, что видит пользователь.
     */
    private fun plural(id: Int, value: Long): String =
        resources.getQuantityString(id, value.toInt(), value.toInt())

    private fun setKeypadEnabled(enabled: Boolean) {
        keypadIds.forEach { id ->
            findViewById<View>(id)?.let { key ->
                key.isEnabled = enabled
                key.alpha = if (enabled) 1f else DISABLED_ALPHA
            }
        }

        // 🔐 Во время задержки отпечаток тоже недоступен — см.
        // offerBiometricUnlock.
        renderBiometricKey()
    }

    /** 🔐 Затирает буфер введённых цифр. */
    private fun clearEntry() {
        entered.clear()
        renderDots()
    }

    private companion object {
        /**
         * Длина PIN.
         *
         * Шесть цифр — миллион вариантов; вместе с растягиванием Argon2id
         * этого достаточно, чтобы перебор на изъятом устройстве занимал
         * годы. Четыре цифры (10 000 вариантов) перебираются за часы.
         */

        /** Шаг обратного отсчёта задержки. */
        const val COOLDOWN_TICK_MILLIS = 1_000L

        /** Прозрачность заблокированной клавиши. */
        const val DISABLED_ALPHA = 0.3f

        const val SECONDS_IN_MINUTE = 60L
        const val SECONDS_IN_HOUR = 3600L
    }
}

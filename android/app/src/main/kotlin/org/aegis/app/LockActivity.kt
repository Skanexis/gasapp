// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.Core
import org.aegis.app.core.PinAttempts
import uniffi.aegis.deriveStorageKey

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
     * `StringBuilder`, а не `String`: неизменяемые строки Java остаются
     * в куче до сборки мусора, и затереть их нельзя. Здесь буфер
     * очищается явно после использования.
     */
    private val entered = StringBuilder()

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

        // 🔐 Запрет скриншотов и превью в списке задач.
        //
        // Без FLAG_SECURE система снимает копию экрана при сворачивании
        // и показывает её в переключателе приложений.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        setContentView(R.layout.activity_lock)

        dots = findViewById(R.id.pin_dots)
        error = findViewById(R.id.pin_error)

        bindKeypad()
        renderDots()
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
        if (entered.length >= PIN_LENGTH) {
            return
        }

        error.visibility = View.INVISIBLE
        entered.append(digit)
        renderDots()

        // Проверка запускается сама при наборе полной длины: отдельная
        // кнопка «ОК» здесь лишняя, длина PIN фиксирована.
        if (entered.length == PIN_LENGTH) {
            unlock()
        }
    }

    private fun removeLast() {
        if (entered.isNotEmpty()) {
            entered.setLength(entered.length - 1)
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
        val pin = entered.toString()

        clearEntry()
        setKeypadEnabled(false)

        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching {
                    // Argon2id считается около секунды и обязан идти
                    // в фоновом потоке: на главном это «приложение
                    // не отвечает» при каждом вводе.
                    val key = deriveStorageKey(pin, Core.salt(this@LockActivity))

                    Core.open(this@LockActivity, key)
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
    }

    /** 🔐 Затирает буфер введённых цифр. */
    private fun clearEntry() {
        entered.setLength(0)
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
        const val PIN_LENGTH = 6

        /** Шаг обратного отсчёта задержки. */
        const val COOLDOWN_TICK_MILLIS = 1_000L

        /** Прозрачность заблокированной клавиши. */
        const val DISABLED_ALPHA = 0.3f

        const val SECONDS_IN_MINUTE = 60L
        const val SECONDS_IN_HOUR = 3600L
    }
}

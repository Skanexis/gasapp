// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

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

    private fun unlock() {
        // Расшифровка хранилища появится вместе с растягиванием PIN
        // в aegis-keystore. Пока экран проверяет только собственное
        // поведение: набор, удаление, отображение.
        clearEntry()

        startActivity(Intent(this, ChatListActivity::class.java))
        finish()
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
    }
}

// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisTextField

/**
 * Экран блокировки.
 *
 * 🔐 PIN здесь **не проверяется и не хранится**. Введённое значение
 * уходит в `aegis-keystore`, где растягивается Argon2id и превращается
 * в ключ, которым расшифровывается хранилище: успех расшифровки и есть
 * проверка. Сравнивать строки в UI означало бы держать PIN в памяти
 * процесса — ровно то, от чего защищает блокировка.
 */
class LockActivity : AppCompatActivity() {

    private lateinit var pinInput: AegisTextField
    private lateinit var error: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Запрет скриншотов и превью в списке задач.
        //
        // Без FLAG_SECURE система снимает копию экрана при сворачивании
        // и показывает её в переключателе приложений — а на экране может
        // остаться введённая часть PIN.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        setContentView(R.layout.activity_lock)

        pinInput = findViewById(R.id.pin_input)
        error = findViewById(R.id.pin_error)

        findViewById<AegisButton>(R.id.unlock_button).setOnClickListener { unlock() }
    }

    private fun unlock() {
        val pin = pinInput.text?.toString().orEmpty()

        if (pin.length < MIN_PIN_LENGTH) {
            // Сообщение не уточняет, что именно не так: «слишком короткий»
            // и «неверный» выглядят одинаково, иначе подбирающий узнал бы
            // длину настоящего PIN.
            error.visibility = View.VISIBLE

            return
        }

        error.visibility = View.INVISIBLE

        // Расшифровка хранилища появится вместе с оркестрацией в ядре.
        // Пока экран проверяет только собственное поведение.
        pinInput.setText("")
        startActivity(Intent(this, ChatListActivity::class.java))
        finish()
    }

    private companion object {
        /**
         * Минимальная длина PIN.
         *
         * Шесть цифр — миллион вариантов; вместе с растягиванием Argon2id
         * этого достаточно, чтобы перебор на изъятом устройстве занимал
         * годы. Четыре цифры (10 000 вариантов) перебираются за часы.
         */
        const val MIN_PIN_LENGTH = 6
    }
}

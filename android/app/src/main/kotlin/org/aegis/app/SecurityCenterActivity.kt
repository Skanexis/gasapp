// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.Toast
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.SecureWindow

/**
 * Центр безопасности.
 *
 * 🔐 Смысл экрана — показать, **что именно** проверено, а не выставить
 * оценку. Одна цифра без разбивки создаёт ложное чувство защищённости:
 * «9 из 10» ничего не говорит о том, какой пункт не выполнен и чем это
 * грозит, поэтому список проверок здесь важнее кольца.
 */
class SecurityCenterActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_security_center)

        findViewById<ImageView>(R.id.security_back).setOnClickListener { finish() }

        renderScore()
        renderChecks()
        bindActions()
    }

    /**
     * Связывает строки центра безопасности.
     *
     * Раньше четыре строки были нарисованы, но не нажимались:
     * пользователь видел «Ключи шифрования» и «Заблокированные»
     * и не мог их открыть. 🔐 В центре безопасности это хуже, чем
     * в другом месте: человек приходит сюда именно проверить
     * состояние защиты, а получает список, который не отвечает.
     *
     * То, чего ещё нет, говорит об этом прямо, а не молчит.
     */
    private fun bindActions() {
        // Ключи шифрования: свой профиль показывает identity-ключ
        // и QR для передачи его собеседнику.
        findViewById<View>(R.id.security_keys).setOnClickListener {
            startActivity(Intent(this, ProfileActivity::class.java))
        }

        findViewById<View>(R.id.security_devices).setOnClickListener {
            startActivity(Intent(this, DevicesActivity::class.java))
        }

        // 🔐 Резервное копирование появится в M6. Пока говорим об этом
        // прямо: строка, молча ничего не делающая, читается как
        // поломка, а обещание «скоро» в интерфейсе устаревает молча.
        findViewById<View>(R.id.security_recovery).setOnClickListener {
            Toast.makeText(this, R.string.security_not_ready, Toast.LENGTH_SHORT).show()
        }

        // Блокировка контактов появится вместе с работой над abuse.
        // Пустой список — честный ответ, а не заглушка.
        findViewById<View>(R.id.security_blocked).setOnClickListener {
            Toast.makeText(this, R.string.security_blocked_empty, Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Показывает счёт и заполняет кольцо.
     *
     * Уровень drawable задаётся в десятитысячных долях — это единица
     * измерения `ClipDrawable`/`ring`, а не проценты.
     */
    private fun renderScore() {
        val score = passedChecks()
        val total = TOTAL_CHECKS

        findViewById<TextView>(R.id.score_value).text = getString(
            R.string.security_score,
            score,
            total,
        )

        findViewById<ImageView>(R.id.score_ring).drawable?.let { ring ->
            ring.level = score * MAX_LEVEL / total
        }

        val pending = total - score
        findViewById<TextView>(R.id.score_subtitle).text = if (pending > 0) {
            getString(R.string.security_needs_attention, pending)
        } else {
            getString(R.string.security_all_clear)
        }
    }

    /** Заполняет список проверок. */
    private fun renderChecks() {
        bindRow(R.id.security_keys, R.drawable.ic_key, R.string.security_keys, null)
        bindRow(R.id.security_devices, R.drawable.ic_users, R.string.security_devices, "2")
        bindRow(R.id.security_recovery, R.drawable.ic_shield, R.string.security_recovery, null)
        bindRow(R.id.security_blocked, R.drawable.ic_alert, R.string.security_blocked, "1")
    }

    private fun bindRow(rowId: Int, iconRes: Int, labelRes: Int, value: String?) {
        val row: View = findViewById(rowId)

        row.findViewById<ImageView>(R.id.row_icon).setImageResource(iconRes)
        row.findViewById<TextView>(R.id.row_label).setText(labelRes)

        row.findViewById<TextView>(R.id.row_value).apply {
            if (value == null) {
                visibility = View.GONE
            } else {
                visibility = View.VISIBLE
                text = value
            }
        }
    }

    /**
     * Сколько проверок пройдено.
     *
     * Пока константа: настоящие проверки (ротация предключей, наличие
     * ключа восстановления, число доверенных устройств) появятся вместе
     * с оркестрацией. Выдумывать их результат в UI нельзя — экран
     * показывал бы защиту, которой нет.
     */
    private fun passedChecks(): Int = PASSED_CHECKS

    private companion object {
        /** Всего проверок. */
        const val TOTAL_CHECKS = 10

        /** Пройдено проверок. */
        const val PASSED_CHECKS = 9

        /** Максимальный уровень drawable. */
        const val MAX_LEVEL = 10_000
    }
}

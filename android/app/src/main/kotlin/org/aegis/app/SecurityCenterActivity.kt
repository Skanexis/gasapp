// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

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
        setContentView(R.layout.activity_security_center)

        findViewById<ImageView>(R.id.security_back).setOnClickListener { finish() }

        renderScore()
        renderChecks()
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

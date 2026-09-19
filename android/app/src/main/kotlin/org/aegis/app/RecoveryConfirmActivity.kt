// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.SecureWindow
import org.aegis.app.components.AegisButton
import uniffi.aegis.checkRecoveryKeyGroup
import kotlin.random.Random

/**
 * Подтверждение записи ключа: ввод трёх случайных групп.
 *
 * # Зачем это обязательно
 *
 * Правило раздела 12.3: без подтверждения половина пользователей
 * потеряет доступ к своим данным — и узнает об этом в тот момент,
 * когда данные понадобятся. Восстановления по почте или SMS нет
 * и не будет, поэтому единственная защита от потери — заставить
 * человека действительно переписать ключ, а не пролистать показ.
 *
 * # Почему группы случайные
 *
 * Первые три запоминаются с экрана без записи. Случайные —
 * из середины и конца — требуют бумаги.
 *
 * # 🔐 Про проверку
 *
 * Сверка идёт в Rust ([checkRecoveryKeyGroup]) и нечувствительна
 * к регистру и к заменам `O`→`0`, `I`/`L`→`1`: человек, переписавший
 * ключ от руки, почти наверняка их спутает, и отвергать его ввод
 * за это значило бы наказывать за ошибку кодировки, а не за то,
 * что он ключ не записал.
 */
class RecoveryConfirmActivity : AppCompatActivity() {

    private var recoveryKey: String? = null

    /** Номера групп, которые спрашиваются у пользователя. */
    private var asked: List<Int> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Тот же флаг, что и на показе ключа: сюда его набирают,
        // и снимок экрана выдал бы три группы из тринадцати.
        // Заодно отбрасываются касания через накрывающее окно:
        // подтверждение на этом экране необратимо (MASVS PLATFORM-3).
        SecureWindow.applyAlways(this)

        setContentView(R.layout.activity_recovery_confirm)

        recoveryKey = intent.getStringExtra(EXTRA_KEY)

        if (recoveryKey == null) {
            // Без ключа подтверждать нечего: экран открыт не тем путём.
            finish()

            return
        }

        findViewById<ImageView>(R.id.confirm_back).setOnClickListener { finish() }

        asked = pickGroups()

        findViewById<TextView>(R.id.confirm_label_first).text =
            getString(R.string.recovery_confirm_group, asked[0] + 1)
        findViewById<TextView>(R.id.confirm_label_second).text =
            getString(R.string.recovery_confirm_group, asked[1] + 1)
        findViewById<TextView>(R.id.confirm_label_third).text =
            getString(R.string.recovery_confirm_group, asked[2] + 1)

        findViewById<AegisButton>(R.id.confirm_submit).setOnClickListener { check() }
        findViewById<AegisButton>(R.id.confirm_show_again).setOnClickListener { showAgain() }
    }

    /** 🔐 Ключ не переживает экран. */
    override fun onDestroy() {
        recoveryKey = null

        super.onDestroy()
    }

    /**
     * Выбирает три разные группы из тринадцати.
     *
     * Берутся из разных третей записи: три подряд идущие группы
     * можно списать с одного взгляда на бумагу, не проверив
     * остальное.
     */
    private fun pickGroups(): List<Int> {
        val random = Random.Default

        return listOf(
            random.nextInt(0, 4),
            random.nextInt(4, 9),
            random.nextInt(9, GROUP_COUNT),
        )
    }

    private fun check() {
        val key = recoveryKey ?: return

        val inputs = listOf(
            findViewById<EditText>(R.id.confirm_input_first),
            findViewById<EditText>(R.id.confirm_input_second),
            findViewById<EditText>(R.id.confirm_input_third),
        )

        val allMatch = asked.zip(inputs).all { (index, field) ->
            runCatching {
                checkRecoveryKeyGroup(key, index.toUInt(), field.text.toString())
            }.getOrDefault(false)
        }

        if (allMatch) {
            done(key)
        } else {
            // Какая именно группа не сошлась, не сообщается: подсказка
            // превратила бы проверку в игру «угадай с трёх попыток»
            // вместо того, чтобы отправить человека к бумаге.
            showStatus(getString(R.string.recovery_confirm_mismatch))
        }
    }

    /**
     * Возвращает к показу ключа.
     *
     * Человек, не успевший переписать, должен иметь путь назад:
     * иначе он либо угадывает, либо теряет ключ навсегда.
     */
    private fun showAgain() {
        startActivity(Intent(this, RecoveryKeyActivity::class.java))
        finish()
    }

    private fun done(key: String) {
        // Ключ уезжает в Recovery Center, чтобы первая копия делалась
        // без повторного набора 52 символов.
        startActivity(
            Intent(this, RecoveryCenterActivity::class.java)
                .putExtra(RecoveryCenterActivity.EXTRA_RECOVERY_KEY, key)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
        )
        finish()
    }

    private fun showStatus(text: String) {
        findViewById<TextView>(R.id.confirm_status).apply {
            this.text = text
            visibility = View.VISIBLE
        }
    }

    companion object {

        /** Ключ, который подтверждается. */
        const val EXTRA_KEY: String = "recovery_key"

        /** Групп в записи ключа: 52 символа по 4 (раздел 12.2). */
        private const val GROUP_COUNT = 13
    }
}

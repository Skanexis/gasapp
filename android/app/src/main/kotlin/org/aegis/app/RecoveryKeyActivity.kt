// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.SecureWindow
import org.aegis.app.components.AegisButton
import uniffi.aegis.generateRecoveryKey

/**
 * Показ ключа восстановления — один раз за всю его жизнь.
 *
 * # 🔐 Почему FLAG_SECURE здесь не спрашивает настройку
 *
 * Остальные экраны ставят флаг по выбору пользователя
 * (`SecureWindow`). Этот — всегда, и выбор не учитывается.
 *
 * Причина в том, что ключ восстановления — единственное, чем
 * расшифровывается вся переписка, и скриншот кладёт его в галерею,
 * а галерея почти на каждом телефоне синхронизируется с облаком.
 * Человек, выключивший блокировку снимков ради удобства в чатах,
 * не имел в виду «выложить ключ от всего архива в Google Photos».
 *
 * Это единственное место приложения, где настройка пользователя
 * не действует, и такое исключение стоит того: цена ошибки здесь
 * несоизмерима с неудобством.
 *
 * # Почему ключ не сохраняется
 *
 * Он не пишется никуда: ни в базу, ни в файл, ни в буфер обмена.
 * Хранимый ключ означал бы, что изъятое устройство отдаёт вместе
 * с собой и все резервные копии, — то есть zero-knowledge backup
 * перестал бы быть zero-knowledge.
 */
class RecoveryKeyActivity : AppCompatActivity() {

    /**
     * Показанный ключ.
     *
     * Уезжает на экран подтверждения, а оттуда — в Recovery Center,
     * чтобы первая копия делалась без повторного набора 52 символов.
     */
    private var recoveryKey: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        // Заодно отбрасываются касания через накрывающее окно:
        // подтверждение на этом экране необратимо (MASVS PLATFORM-3).
        SecureWindow.applyAlways(this)

        setContentView(R.layout.activity_recovery_key)

        findViewById<ImageView>(R.id.key_back).setOnClickListener { finish() }

        val generated = runCatching { generateRecoveryKey() }.getOrNull()

        if (generated == null) {
            // Сбой генератора случайных чисел — не то, о чём можно
            // умолчать: ключ, выведенный из плохой энтропии, хуже
            // отсутствия ключа.
            findViewById<TextView>(R.id.key_value).setText(R.string.recovery_key_failed)
            findViewById<AegisButton>(R.id.key_written).isEnabled = false

            return
        }

        recoveryKey = generated.display

        // Группы разносятся по строкам: 52 символа в одну строку
        // на телефоне не читаются, а переписывать их придётся руками.
        findViewById<TextView>(R.id.key_value).text = wrap(generated.display)

        findViewById<AegisButton>(R.id.key_written).setOnClickListener { confirm() }
    }

    /** 🔐 Ключ не переживает экран. */
    override fun onDestroy() {
        recoveryKey = null

        super.onDestroy()
    }

    private fun confirm() {
        val key = recoveryKey ?: return

        startActivity(
            Intent(this, RecoveryConfirmActivity::class.java)
                .putExtra(RecoveryConfirmActivity.EXTRA_KEY, key),
        )

        // Экран закрывается: вернуться к показу можно только через
        // кнопку на экране подтверждения, и это осознанно —
        // «назад» не должно листать ключ туда-сюда.
        finish()
    }

    /**
     * Разбивает запись ключа на строки по три группы.
     *
     * `AEGIS-7F2K-9QMD-X4RT` в строке — это ширина, которая помещается
     * на любом телефоне и остаётся читаемой моноширинным шрифтом.
     */
    private fun wrap(display: String): String {
        val parts = display.split('-')
        val prefix = parts.firstOrNull().orEmpty()
        val groups = parts.drop(1)

        return groups
            .chunked(GROUPS_PER_LINE)
            .mapIndexed { index, line ->
                // Приставка стоит только в первой строке: она не часть
                // ключа, а метка формата.
                if (index == 0) "$prefix-${line.joinToString("-")}" else line.joinToString("-")
            }
            .joinToString("\n")
    }

    private companion object {

        /** Сколько групп помещается в строку на телефоне. */
        const val GROUPS_PER_LINE = 3
    }
}

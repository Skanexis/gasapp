// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.widget.TextView
import androidx.activity.addCallback
import androidx.appcompat.app.AppCompatActivity
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.core.SecureWindow

/**
 * Объяснение смены ключа безопасности после восстановления
 * (раздел 12.5 плана).
 *
 * # Зачем этот экран
 *
 * Резервная копия не содержит ни приватного identity-ключа, ни
 * состояния храповика. Это решение, а не упущение: старое состояние
 * храповика в копии означало бы возврат к уже использованным message
 * key, то есть повторное использование ключа в AEAD — раскрытие
 * и открытых текстов, и подключа аутентификации.
 *
 * Цена решения в том, что собеседники увидят «ключ безопасности
 * изменился» — ровно то предупреждение, которым приложение сообщает
 * о возможной подмене. Не объяснить это здесь значит приучить
 * человека игнорировать настоящую тревогу: он однажды увидел её без
 * причины и перестал читать.
 *
 * # Почему нельзя закрыть кнопкой «назад»
 *
 * Экран заканчивает восстановление и не имеет пути назад: возвращаться
 * некуда — предыдущий экран уже закрыт. Оба варианта («проверить
 * сейчас» и «позже») ведут вперёд.
 */
class IdentityChangedActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        // 🔐 Касания через накрывающее окно отбрасываются:
        // здесь разблокируют отправку контакту со сменившимся ключом,
        // то есть подменённое нажатие стоит дороже неудобства
        // (MASVS PLATFORM-3).
        SecureWindow.blockObscuredTouches(this)

        setContentView(R.layout.activity_identity_changed)

        val applied = intent.getIntExtra(EXTRA_APPLIED, 0)
        val backupAt = intent.getLongExtra(EXTRA_BACKUP_AT, 0L)

        // 🔐 Дата состояния копии — чтобы неполная цепочка была видна
        // (находка B-1): восстановление без последних файлов проходит,
        // возвращая прежнее состояние, и проверить полноту приложению нечем.
        findViewById<TextView>(R.id.identity_changed_summary).text =
            if (backupAt > 0L) {
                getString(R.string.identity_changed_restored_as_of, applied, backupDate(backupAt))
            } else {
                getString(R.string.identity_changed_restored_count, applied)
            }

        findViewById<GasAppButton>(R.id.identity_changed_verify).setOnClickListener {
            // Сверять safety number идут в список контактов: у каждого
            // собеседника он свой, и общей кнопки «проверить всех»
            // не существует — сверка личная по определению.
            goTo(ContactsActivity::class.java)
        }

        findViewById<GasAppButton>(R.id.identity_changed_later).setOnClickListener {
            goTo(ChatListActivity::class.java)
        }

        // Кнопка «назад» ведёт к списку чатов, а не наружу.
        //
        // Восстановление завершено, предыдущий экран закрыт: обычное
        // «назад» выбросило бы из приложения на середине объяснения
        // про сменившийся ключ.
        //
        // Через OnBackPressedDispatcher, а не переопределением
        // `onBackPressed`: последнее объявлено устаревшим, не вызывает
        // `super` (на что ругается lint и ронял сборку проверок) и
        // не работает с предиктивным жестом «назад» на Android 13+.
        onBackPressedDispatcher.addCallback(this) {
            goTo(ChatListActivity::class.java)
        }
    }

    private fun backupDate(millis: Long): String =
        java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.LONG, java.text.DateFormat.SHORT)
            .format(java.util.Date(millis))

    private fun goTo(screen: Class<*>) {
        startActivity(
            Intent(this, screen)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }

    companion object {

        /** Сколько записей восстановлено — для строки итога. */
        const val EXTRA_APPLIED: String = "applied"

        /** Когда сделана последняя восстановленная копия, мс. */
        const val EXTRA_BACKUP_AT: String = "backup_at"
    }
}

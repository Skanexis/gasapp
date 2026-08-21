// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisTextField
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import uniffi.aegis.FfiContact

/**
 * Добавление контакта по ссылке `aegis://contact/...`.
 *
 * # 🔐 Почему нажатие на ссылку не добавляет контакт сразу
 *
 * Ссылка приходит откуда угодно: из чужого чата, с наклейки, от
 * незнакомца. Она не подписана и подписана быть не может — ключ как
 * раз и передаётся. Молчаливое добавление означало бы, что чужая
 * ссылка заводит запись в списке контактов без ведома пользователя.
 *
 * Поэтому ссылка из внешнего намерения только подставляется в поле:
 * решение принимает человек.
 *
 * # Про имя в ссылке
 *
 * Имя выбирает тот, кто сделал ссылку, и ядро сверяет его с сервером:
 * ключ, зарегистрированный под другим именем, добавлен не будет. Это
 * не делает сервер доверенным — ключ пришёл со ссылки, из канала,
 * которого сервер не видел.
 */
class AddContactActivity : AppCompatActivity() {

    private lateinit var input: AegisTextField
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_add_contact)

        input = findViewById(R.id.add_contact_link)
        status = findViewById(R.id.add_contact_status)

        findViewById<AegisButton>(R.id.add_contact_confirm).setOnClickListener { addContact() }

        prefillFromIntent(intent)
    }

    /**
     * Подхватывает ссылку, если экран открыт повторно новым намерением.
     *
     * Без этого вторая ссылка, открытая при уже запущенном экране,
     * молча не подставилась бы, и пользователь добавил бы предыдущую.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        prefillFromIntent(intent)
    }

    /**
     * 🔐 Очищает поле и результат при уходе с экрана.
     *
     * Ссылка содержит identity-ключ и имя контакта; в снимке для
     * переключателя задач им не место.
     */
    override fun onStop() {
        super.onStop()

        input.setText("")
        status.text = ""
    }

    /**
     * Подставляет ссылку из внешнего намерения.
     *
     * 🔐 Только подставляет. Само намерение приходит от системы по
     * схеме `aegis://`, но отправить его может любое приложение
     * на устройстве.
     */
    private fun prefillFromIntent(intent: Intent) {
        val uri = intent.data?.toString()
            ?: intent.getStringExtra(EXTRA_LINK)
            ?: return

        input.setText(uri)
    }

    private fun addContact() {
        val uri = input.text?.toString().orEmpty().trim()

        if (uri.isEmpty()) {
            return
        }

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().addContactFromLink(uri, System.currentTimeMillis())
                }
            }

            result
                .onSuccess(::showAdded)
                // Ядро не различает «битая ссылка» и «имя чужое»
                // отдельными типами ошибок, поэтому текст объединяет
                // оба случая. Разделять их значило бы подсказывать
                // тому, кто подбирает ссылку, что именно не сошлось.
                .onFailure { status.setText(R.string.add_contact_invalid) }
        }
    }

    private fun showAdded(contact: FfiContact) {
        status.text = when (val name = contact.username) {
            null -> getString(R.string.add_contact_added_unnamed)
            else -> getString(R.string.add_contact_added, name)
        }

        input.setText("")
    }

    companion object {
        /** Ссылка, переданная не через `data`, а явным extra. */
        const val EXTRA_LINK = "contact_link"
    }
}

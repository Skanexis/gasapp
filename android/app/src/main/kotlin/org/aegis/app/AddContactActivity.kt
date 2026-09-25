// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
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
        findViewById<android.view.View>(R.id.screen_back).setOnClickListener { finish() }

        input = findViewById(R.id.add_contact_link)
        // Правка ссылки снимает прошлый итог: он относился к другой ссылке.
        input.doAfterTextChanged { input.hasError = false }
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
        status.visibility = View.GONE
    }

    /**
     * Итог добавления цветом и значком (состояние — не только цветом,
     * раздел 20.5): галочка у успеха, круг-предупреждение у отказа.
     */
    private fun showStatus(text: CharSequence, ok: Boolean) {
        val color = getColor(if (ok) R.color.status_ok else R.color.status_error)

        status.text = text
        status.setTextColor(color)
        status.setCompoundDrawablesRelativeWithIntrinsicBounds(
            if (ok) R.drawable.ic_check_small else R.drawable.ic_alert_small,
            0,
            0,
            0,
        )
        status.compoundDrawablesRelative[0]?.setTint(color)
        status.visibility = View.VISIBLE
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
                .onFailure {
                    input.hasError = true
                    showStatus(getString(R.string.add_contact_invalid), ok = false)
                }
        }
    }

    private fun showAdded(contact: FfiContact) {
        // 🔐 Имя уже известно под другим ключом.
        //
        // Это может быть переустановка или восстановление из копии —
        // а может быть подсунутая ссылка, выдающая чужой ключ
        // за знакомого. Отличить может только сверка вживую, поэтому
        // человек не просто предупреждается, а сразу попадает на неё.
        //
        // ⚠️ Прежний контакт остаётся на месте и своей отметки
        // о сверке не теряет; новый начинается несверенным.
        if (contact.keyChanged) {
            showStatus(getString(R.string.add_contact_key_changed, contact.username.orEmpty()), ok = false)
            input.setText("")

            startActivity(
                Intent(this, SafetyNumberActivity::class.java)
                    .putExtra(SafetyNumberActivity.EXTRA_ACCOUNT_ID, contact.accountId)
                    .putExtra(SafetyNumberActivity.EXTRA_PEER_NAME, contact.username.orEmpty()),
            )

            return
        }

        showStatus(
            when (val name = contact.username) {
                null -> getString(R.string.add_contact_added_unnamed)
                else -> getString(R.string.add_contact_added, name)
            },
            ok = true,
        )

        input.setText("")
    }

    companion object {
        /** Ссылка, переданная не через `data`, а явным extra. */
        const val EXTRA_LINK = "contact_link"
    }
}

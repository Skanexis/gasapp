// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.res.ResourcesCompat
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.components.GasAppTextField
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import uniffi.gasapp.FfiContact
import uniffi.gasapp.FfiException
import uniffi.gasapp.canonicalUsername

/**
 * Новый собеседник — по `@имени` или по QR-коду.
 *
 * # 🔐 Два пути разной силы
 *
 * **Имя** превращает в ключ сервер. Поэтому ключ сверяется открытым
 * журналом ключей (раздел 9.7 спецификации): если аккаунту больше суток,
 * писать можно сразу; новому — после суток в журнале или личной сверки.
 *
 * **QR-код** несёт сам ключ и приходит мимо сервера — это точная сверка
 * без ожидания. Его сканирует встроенный сканер ([ScanActivity]).
 *
 * # Почему без ссылки
 *
 * Прежде контакт добавлялся вставкой ссылки `gasapp://contact/…` —
 * длинной строки с ключом. Её убрали по решению владельца: для людей
 * имя и QR понятнее, а ссылка давала ровно то же, что QR. Вместе с ней
 * убран и экспорт этого экрана: внешние приложения больше не могут
 * открыть его с чужой ссылкой.
 */
class AddContactActivity : AppCompatActivity() {

    private lateinit var input: GasAppTextField
    private lateinit var status: TextView
    private lateinit var openButton: GasAppButton

    private val scan = registerForActivityResult(ScanActivity.Contract()) { payload ->
        if (payload != null) addScanned(payload)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_add_contact)
        findViewById<View>(R.id.screen_back).setOnClickListener { finish() }

        input = findViewById(R.id.add_contact_username)
        status = findViewById(R.id.add_contact_status)
        openButton = findViewById(R.id.add_contact_open)

        // Вариант «видимый пароль» ставит моноширинный шрифт —
        // возвращается шрифт макета.
        input.typeface = ResourcesCompat.getFont(this, R.font.inter)
        input.doAfterTextChanged { resetStatus() }
        // «Перейти» на экранной клавиатуре и Enter на подключённой:
        // вторая приходит не действием, а нажатием клавиши.
        input.setOnEditorActionListener { _, action, event ->
            val enter = event?.keyCode == android.view.KeyEvent.KEYCODE_ENTER &&
                event.action == android.view.KeyEvent.ACTION_DOWN
            (action == EditorInfo.IME_ACTION_GO || enter).also { if (it) openByUsername() }
        }

        openButton.setOnClickListener { openByUsername() }
        findViewById<GasAppButton>(R.id.add_contact_scan).apply {
            setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_qr, 0, 0, 0)
            compoundDrawablesRelative[0]?.setTint(currentTextColor)
            setOnClickListener {
                scan.launch(ScanActivity.Request(R.string.add_contact_scan, R.string.scan_hint_contact))
            }
        }

        input.requestFocus()
    }

    /** 🔐 Введённое имя не остаётся на экране, уходящем в фон. */
    override fun onStop() {
        super.onStop()
        input.setText("")
    }

    private fun openByUsername() {
        // Каноничная форма: «@Bob» находит «bob», двойник с кириллицей
        // не находит никого.
        val username = runCatching { canonicalUsername(input.text?.toString().orEmpty()) }
            .getOrNull()
            ?.takeIf { it.isNotEmpty() }
            ?: return showStatus(getString(R.string.onboarding_error_username), ok = false)

        // Своё имя — не собеседник (ядро отвергнет его и само).
        if (username == runCatching { Core.messenger().ownUsername() }.getOrNull()) {
            return showStatus(getString(R.string.new_chat_own_name), ok = false)
        }

        openButton.isLoading = true

        lifecycleScope.launch {
            val found = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().discoverContact(username, System.currentTimeMillis()) }
            }

            openButton.isLoading = false

            found
                .onSuccess { contact -> openChat(contact, username) }
                .onFailure { failure ->
                    showStatus(
                        getString(
                            if (failure is FfiException.IdentityChanged) R.string.key_changed_title else R.string.new_chat_not_found,
                        ),
                        ok = false,
                    )
                }
        }
    }

    /**
     * Добавляет собеседника по отсканированному коду.
     *
     * 🔐 Разбирает и проверяет код ядро (`addContactFromLink`): имя
     * из кода сверяется с сервером, ключ — только из кода. Чужой код
     * (не контакт GasApp) отвергается там же.
     */
    private fun addScanned(payload: String) {
        if (payload == runCatching { Core.messenger().ownContactLink() }.getOrNull()) {
            return showStatus(getString(R.string.add_contact_own_link), ok = false)
        }

        lifecycleScope.launch {
            val added = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().addContactFromLink(payload, System.currentTimeMillis()) }
            }

            added
                .onSuccess(::showAdded)
                .onFailure { showStatus(getString(R.string.add_contact_scan_invalid), ok = false) }
        }
    }

    private fun showAdded(contact: FfiContact) {
        // 🔐 Имя уже известно под другим ключом: переустановка — или
        // подмена. Отличить может только сверка вживую, поэтому человек
        // сразу попадает на неё. Прежний контакт отметку не теряет.
        if (contact.keyChanged) {
            showStatus(getString(R.string.add_contact_key_changed, contact.username.orEmpty()), ok = false)

            startActivity(
                Intent(this, SafetyNumberActivity::class.java)
                    .putExtra(SafetyNumberActivity.EXTRA_ACCOUNT_ID, contact.accountId)
                    .putExtra(SafetyNumberActivity.EXTRA_PEER_NAME, contact.username.orEmpty()),
            )

            return
        }

        openChat(contact, contact.username.orEmpty())
    }

    private fun openChat(contact: FfiContact, username: String) {
        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra(ChatActivity.EXTRA_CHAT_ID, contact.chatId.orEmpty())
                .putExtra(ChatActivity.EXTRA_CHAT_NAME, username)
                .putExtra(ChatActivity.EXTRA_PEER_USERNAME, username)
                .putExtra(ChatActivity.EXTRA_VERIFIED, contact.verified),
        )
        finish()
    }

    /**
     * Итог цветом и значком (состояние — не только цветом, раздел 20.5):
     * на место подсказки под полем, как в UI kit.
     */
    private fun showStatus(text: CharSequence, ok: Boolean) {
        val color = getColor(if (ok) R.color.status_ok else R.color.status_error)

        input.hasError = !ok
        status.text = text
        status.setTextColor(color)
        status.setCompoundDrawablesRelativeWithIntrinsicBounds(
            if (ok) R.drawable.ic_check_small else R.drawable.ic_alert_small,
            0,
            0,
            0,
        )
        status.compoundDrawablesRelative[0]?.setTint(color)
    }

    private fun resetStatus() {
        if (!input.hasError) return

        input.hasError = false
        status.setText(R.string.add_contact_username_helper)
        status.setTextColor(getColor(R.color.text_muted))
        status.setCompoundDrawablesRelative(null, null, null, null)
    }
}

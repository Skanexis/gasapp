// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppTextField
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.core.TouchTarget
import org.gasapp.app.ui.BottomNav
import org.gasapp.app.ui.ChatListAdapter
import org.gasapp.app.ui.ChatSummary
import org.gasapp.app.ui.EmptyState
import org.gasapp.app.ui.RowDivider
import uniffi.gasapp.FfiContact

/**
 * Экран контактов.
 *
 * Переиспользует [ChatListAdapter]: строка контакта и строка чата
 * совпадают по составу — аватар, имя, подпись. Второй адаптер с той
 * же вёрсткой разошёлся бы с первым при первой правке.
 *
 * # Что показывается
 *
 * 🔐 Имя контакта — подсказка, а не удостоверение: его называет сам
 * контакт. Метка «верифицирован» ставится только после ручной сверки
 * safety number и означает совсем другое — что ключ проверен человеком.
 * Поэтому неверифицированный контакт показывается без метки, а не
 * с меткой «не проверен»: отсутствие подтверждения и есть состояние
 * по умолчанию, и лишняя метка приучила бы её не замечать.
 */
class ContactsActivity : AppCompatActivity() {

    private lateinit var adapter: ChatListAdapter
    private lateinit var list: RecyclerView
    private lateinit var empty: View

    /** Последний прочитанный из ядра список — источник для фильтра. */
    private var loaded: List<FfiContact> = emptyList()

    /** Текущая строка фильтра. */
    private var filter: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_contacts)

        list = findViewById(R.id.contact_list)
        empty = findViewById(R.id.contact_list_empty)
        EmptyState.bind(
            empty,
            icon = R.drawable.ic_users,
            title = R.string.contacts_empty_title,
            body = R.string.contacts_empty_real,
            action = R.string.add_contact,
        ) { findViewById<View>(R.id.add_contact).performClick() }

        adapter = ChatListAdapter(onClick = ::openChat)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        list.addItemDecoration(RowDivider(this))

        findViewById<View>(R.id.add_contact).setOnClickListener {
            startActivity(Intent(this, AddContactActivity::class.java))
        }

        // 🔐 Иконка 24dp, область нажатия — 48dp (WCAG 2.5.5).
        // Вид не меняется: увеличивается только то, куда можно
        // попасть. Подробности — в TouchTarget.
        TouchTarget.expand(findViewById(R.id.add_contact))
        // Поле над списком фильтрует контакты, а не ищет по переписке:
        // поиск по сообщениям живёт на своём экране, и подмешивать
        // сюда его результаты значило бы показывать в списке людей
        // строки из чужих разговоров.
        findViewById<GasAppTextField>(R.id.contact_search)
            .addTextChangedListener(object : TextWatcher {
                override fun afterTextChanged(text: Editable?) {
                    filter = text?.toString().orEmpty().trim()
                    render(loaded)
                }

                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit

                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            })
        BottomNav.bind(this, BottomNav.Tab.Contacts)
    }

    /**
     * 🔐 Очищает список при уходе с экрана.
     *
     * Список контактов — это тоже сведения о том, с кем пользователь
     * связан, и в снимке для переключателя задач ему не место.
     */
    override fun onStop() {
        super.onStop()

        adapter.clear()
        loaded = emptyList()
    }

    override fun onStart() {
        super.onStart()
        loadContacts()
    }

    /**
     * Читает контакты из ядра.
     *
     * Уходит на `Dispatchers.IO`: переход через границу FFI
     * блокирующий, а внутри — чтение зашифрованного хранилища.
     */
    private fun loadContacts() {
        lifecycleScope.launch {
            val contacts = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().contacts() }.getOrDefault(emptyList())
            }

            loaded = contacts
            render(contacts)
        }
    }

    private fun render(contacts: List<FfiContact>) {
        val visible = when {
            filter.isEmpty() -> contacts
            // Контакт без имени фильтру не соответствует никогда:
            // сопоставлять запрос с идентификатором аккаунта значило бы
            // находить людей по строке, которую пользователь не вводил
            // и не видел.
            else -> contacts.filter { contact ->
                contact.username?.contains(filter, ignoreCase = true) == true
            }
        }

        val items = visible.map { contact ->
            val name = contact.username ?: getString(R.string.contact_no_username)

            ChatSummary(
                chatId = contact.accountId,
                name = name,
                preview = when {
                    contact.username == null -> ""
                    contact.verified -> getString(R.string.contact_verified, contact.username)
                    else -> getString(R.string.contact_username, contact.username)
                },
                time = "",
                verified = contact.verified,
            )
        }

        adapter.submit(items)

        val hasContacts = items.isNotEmpty()
        list.visibility = if (hasContacts) View.VISIBLE else View.GONE
        empty.visibility = if (hasContacts) View.GONE else View.VISIBLE
    }

    /**
     * Открывает профиль контакта.
     *
     * Профиль, а не сразу переписку: на нём видно состояние ключа,
     * и это единственное место, откуда ведёт путь к сверке. Открывать
     * чат в один шаг значило бы прятать сверку глубже, чем отправку
     * сообщения — при том что она важнее.
     */
    private fun openChat(contact: ChatSummary) {
        startActivity(
            Intent(this, ContactProfileActivity::class.java)
                .putExtra(ContactProfileActivity.EXTRA_ACCOUNT_ID, contact.chatId),
        )
    }

}

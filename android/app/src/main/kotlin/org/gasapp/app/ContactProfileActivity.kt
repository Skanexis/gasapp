// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.initialsOf
import org.gasapp.app.ui.paintAvatar
import uniffi.gasapp.FfiContact

/**
 * Профиль контакта.
 *
 * # Что здесь главное
 *
 * Состояние ключа, а не имя и аватар. Имя контакт называет сам,
 * и оно ничем не подтверждено: «Банк» в имени не делает собеседника
 * банком. Сверенный ключ — единственное, что говорит, с кем на самом
 * деле идёт переписка.
 *
 * 🔐 Несверенный контакт не помечается тревожным цветом. Красный
 * на состоянии по умолчанию быстро перестают замечать, и тогда он
 * не сработает там, где действительно важен — при смене ключа.
 */
class ContactProfileActivity : AppCompatActivity() {

    private lateinit var nameView: TextView
    private lateinit var verifiedView: TextView
    private lateinit var hintView: TextView
    private lateinit var keyView: TextView

    /** Контакт, показанный на экране. */
    private var contact: FfiContact? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_contact_profile)
        findViewById<android.view.View>(R.id.contact_profile_back).setOnClickListener { finish() }


        nameView = findViewById(R.id.contact_profile_name)
        verifiedView = findViewById(R.id.contact_profile_verified)
        hintView = findViewById(R.id.contact_profile_hint)
        keyView = findViewById(R.id.contact_profile_key)

        findViewById<View>(R.id.contact_profile_verify).setOnClickListener { verify() }
        findViewById<View>(R.id.contact_profile_open_chat).setOnClickListener { openChat() }
    }

    /**
     * 🔐 Очищает экран при уходе.
     *
     * Имя и ключ контакта — сведения о том, с кем связан пользователь.
     * В снимке для переключателя задач им не место.
     */
    override fun onStop() {
        super.onStop()

        nameView.text = ""
        keyView.text = ""
        findViewById<TextView>(R.id.contact_profile_avatar).text = ""
        contact = null
    }

    override fun onStart() {
        super.onStart()
        load()
    }

    /**
     * Находит контакт в ядре по идентификатору аккаунта.
     *
     * Читается заново, а не передаётся целиком через intent: за время
     * между экранами контакт мог быть сверен, и показывать прежнее
     * состояние ключа значило бы соврать о самом важном на экране.
     */
    private fun load() {
        val accountId = intent.getStringExtra(EXTRA_ACCOUNT_ID).orEmpty()

        if (accountId.isEmpty()) {
            finish()

            return
        }

        lifecycleScope.launch {
            val found = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().contacts().firstOrNull { it.accountId == accountId }
                }.getOrNull()
            }

            if (found == null) {
                finish()

                return@launch
            }

            contact = found
            render(found)
        }
    }

    private fun render(contact: FfiContact) {
        val name = contact.username ?: getString(R.string.contact_no_username)
        nameView.text = name
        findViewById<TextView>(R.id.contact_profile_avatar).text = initialsOf(name)
        paintAvatar(findViewById(R.id.contact_profile_avatar), name)
        keyView.text = formatKey(contact.identity)

        // Состояние не только цветом (раздел 20.5): у сверенного —
        // галочка на аватаре и в пилюле.
        findViewById<View>(R.id.contact_profile_badge).visibility =
            if (contact.verified) View.VISIBLE else View.GONE

        if (contact.verified) {
            verifiedView.setText(R.string.contact_profile_verified)
            verifiedView.setTextColor(ContextCompat.getColor(this, R.color.status_ok))
            verifiedView.setBackgroundResource(R.drawable.bg_pill_ok)
            verifiedView.setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_check_small, 0, 0, 0)
            verifiedView.compoundDrawablesRelative[0]?.setTint(ContextCompat.getColor(this, R.color.status_ok))
            hintView.visibility = View.GONE
        } else {
            verifiedView.setText(R.string.contact_profile_unverified)
            verifiedView.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            verifiedView.setBackgroundResource(R.drawable.bg_pill_neutral)
            verifiedView.setCompoundDrawablesRelative(null, null, null, null)
            hintView.visibility = View.VISIBLE
        }
    }

    /**
     * Разбивает ключ на группы по четыре знака.
     *
     * Сплошные 64 символа сверяют невнимательно: глаз теряет место,
     * и человек проверяет края, пропуская середину.
     */
    private fun formatKey(identity: ByteArray): String =
        identity.joinToString("") { byte -> "%02X".format(byte) }
            .chunked(GROUP_SIZE)
            // По четыре группы в строке: сетка, а не сплошной перенос,
            // где строки обрывались на разных местах.
            .chunked(GROUPS_PER_LINE)
            .joinToString("\n") { line -> line.joinToString(" ") }

    /**
     * Открывает сверку safety number.
     *
     * 🔐 Отметку «сверен» ставит только этот путь: она означает
     * «я лично сравнил», и выдавать её за что-то другое — например,
     * за переход по ссылке — значит обесценить её там, где на неё
     * полагаются.
     */
    private fun verify() {
        // ⚠️ Прежде здесь стояло `contact?.username ?: return`: контакт
        // без имени — добавленный по ссылке, где имени нет, — сверить
        // было нельзя вовсе. Имя нужно только для подписи экрана;
        // ключ ядро находит по счёту.
        val current = contact ?: return

        startActivity(
            Intent(this, SafetyNumberActivity::class.java)
                .putExtra(SafetyNumberActivity.EXTRA_ACCOUNT_ID, current.accountId)
                .putExtra(SafetyNumberActivity.EXTRA_PEER_NAME, current.username.orEmpty()),
        )
    }

    private fun openChat() {
        val current = contact ?: return
        val chatId = current.chatId ?: return

        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra(ChatActivity.EXTRA_CHAT_ID, chatId)
                .putExtra(
                    ChatActivity.EXTRA_CHAT_NAME,
                    current.username ?: getString(R.string.contact_no_username),
                )
                .putExtra(ChatActivity.EXTRA_PEER_USERNAME, current.username.orEmpty())
                .putExtra(ChatActivity.EXTRA_VERIFIED, current.verified),
        )
    }

    companion object {
        /** Идентификатор аккаунта контакта. */
        const val EXTRA_ACCOUNT_ID = "account_id"

        /** По сколько знаков группировать ключ. */
        private const val GROUP_SIZE = 4

        /** Групп в строке: 16 групп ключа — сетка 4 × 4. */
        private const val GROUPS_PER_LINE = 4
    }
}

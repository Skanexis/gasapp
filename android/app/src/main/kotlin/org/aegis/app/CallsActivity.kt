// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.components.AegisButton
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.BottomNav

/**
 * Журнал звонков.
 *
 * # Что здесь есть сейчас
 *
 * Пустой журнал и фильтры. Сами звонки появятся в M9 вместе с WebRTC
 * и сквозным шифрованием медиапотока.
 *
 * Экран сделан сейчас, потому что вкладка «Звонки» есть в нижней
 * навигации макета: нарисованная, но не открывающая ничего вкладка
 * читается как поломка приложения, а не как незавершённая функция.
 *
 * 🔐 Пустой список, а не заглушка «скоро будет»: пустое состояние —
 * честный ответ на вопрос «были ли звонки», а обещание в интерфейсе
 * устаревает молча и остаётся висеть после того, как функция уже
 * появилась.
 *
 * # Где будет храниться журнал
 *
 * 🔐 Только на устройстве, в той же зашифрованной базе, что и
 * переписка. Серверу журнал не отдаётся: кто кому звонил и когда —
 * тот же социальный граф, что и переписка, только точнее по времени.
 */
class CallsActivity : AppCompatActivity() {

    private lateinit var list: RecyclerView
    private lateinit var empty: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_calls)

        list = findViewById(R.id.calls_list)
        empty = findViewById(R.id.calls_empty)

        list.layoutManager = LinearLayoutManager(this)

        bindFilters()
        bindNavigation()
        BottomNav.highlight(this, BottomNav.Tab.Calls)

        render()
    }

    override fun onStart() {
        super.onStart()
        render()
    }

    /**
     * Показывает журнал.
     *
     * Пока звонков нет, список скрыт, а на экране — пустое состояние.
     * Когда появится хранилище журнала, здесь будет чтение из ядра
     * тем же способом, что в списке чатов.
     */
    private fun render() {
        val calls = emptyList<Unit>()

        val hasCalls = calls.isNotEmpty()
        list.visibility = if (hasCalls) View.VISIBLE else View.GONE
        empty.visibility = if (hasCalls) View.GONE else View.VISIBLE
    }

    /**
     * Переключает фильтр журнала.
     *
     * Выбранный фильтр показан заливкой, невыбранный — без неё:
     * вариантов два, и подсвечивать оба значило бы не показывать
     * ничего.
     */
    private fun bindFilters() {
        val all = findViewById<AegisButton>(R.id.calls_filter_all)
        val missed = findViewById<AegisButton>(R.id.calls_filter_missed)

        all.setOnClickListener {
            all.variant = AegisButton.Variant.Secondary
            missed.variant = AegisButton.Variant.Ghost
            render()
        }

        missed.setOnClickListener {
            all.variant = AegisButton.Variant.Ghost
            missed.variant = AegisButton.Variant.Secondary
            render()
        }
    }

    /**
     * Связывает вкладки нижней навигации.
     *
     * `finish()` после перехода: вкладки — разделы одного уровня,
     * и накопление их в стеке заставляло бы жать «назад» столько раз,
     * сколько было переключений.
     */
    private fun bindNavigation() {
        findViewById<View>(R.id.nav_chats).setOnClickListener {
            startActivity(Intent(this, ChatListActivity::class.java))
            finish()
        }
        // Вкладка «Звонки» не обрабатывается: этот экран уже открыт,
        // и переход на себя перезапустил бы его, потеряв выбранный
        // фильтр.
        findViewById<View>(R.id.nav_contacts).setOnClickListener {
            startActivity(Intent(this, ContactsActivity::class.java))
            finish()
        }
        findViewById<View>(R.id.nav_settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
            finish()
        }
    }
}

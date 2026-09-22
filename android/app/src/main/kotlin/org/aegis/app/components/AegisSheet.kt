// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.core.content.ContextCompat
import org.aegis.app.R

/**
 * Нижняя панель действий в стиле AEGIS.
 *
 * # Почему не системный диалог
 *
 * `AlertDialog` рисуется темой платформы: другой шрифт, другие
 * скругления, другие цвета. Панель, выпадающая из-под низа экрана
 * и выглядящая как чужое приложение, ломает то немногое, на чём
 * держится доверие к интерфейсу — узнаваемость.
 *
 * Метрики взяты из UI kit (.sheet): фон raised, скругление 24 сверху,
 * ручка 36×4, заголовок 600/15 по центру.
 *
 * # Про опасные действия
 *
 * 🔐 Пункт можно пометить как разрушительный — он красится в цвет
 * ошибки. Это не украшение: удаление и отзыв ключей необратимы,
 * и они не должны выглядеть так же, как «копировать».
 */
class AegisSheet private constructor(
    private val activity: Activity,
    private val title: String,
) {

    private val items = mutableListOf<Item>()

    /** Пункт панели. */
    private data class Item(
        val label: String,
        @DrawableRes val icon: Int?,
        val emoji: String?,
        val destructive: Boolean,
        val action: () -> Unit,
    )

    /** Добавляет пункт со значком. */
    fun action(
        label: String,
        @DrawableRes icon: Int? = null,
        destructive: Boolean = false,
        action: () -> Unit,
    ): AegisSheet {
        items.add(Item(label, icon, null, destructive, action))

        return this
    }

    /**
     * Добавляет пункт с эмодзи вместо значка.
     *
     * Нужен реакциям: рисовать для каждой эмодзи свой вектор значило бы
     * держать набор картинок там, где хватает символа.
     */
    fun emoji(symbol: String, label: String, action: () -> Unit): AegisSheet {
        items.add(Item(label, null, symbol, false, action))

        return this
    }

    /** Показывает панель. */
    fun show() {
        val dialog = Dialog(activity, R.style.AegisSheetDialog)
        val view = LayoutInflater.from(activity).inflate(R.layout.view_action_sheet, null)

        view.findViewById<TextView>(R.id.sheet_title).apply {
            text = title
            visibility = if (title.isEmpty()) View.GONE else View.VISIBLE
        }

        val container = view.findViewById<LinearLayout>(R.id.sheet_items)

        for (item in items) {
            container.addView(rowFor(item, container, dialog))
        }

        // До setContentView: после того как у окна есть содержимое,
        // requestFeature бросает AndroidRuntimeException. Прежде вызов
        // стоял ниже, в блоке window, и каждая панель приложения — меню
        // чата, вложения, действия над сообщением, реакции, таймер,
        // автоблокировка, «открыть/удалить» в хранилище — роняла
        // приложение при открытии. Ни один тест панель не показывал;
        // нашёл DialogScreenshotTest, подтверждено на эмуляторе.
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.setContentView(view)

        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
            )
            setGravity(Gravity.BOTTOM)

            // Затемнение фона: панель — модальный шаг, и остальной
            // экран не должен выглядеть доступным для нажатия.
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            setDimAmount(DIM_AMOUNT)
        }

        dialog.show()
    }

    private fun rowFor(item: Item, parent: ViewGroup, dialog: Dialog): View {
        val row = LayoutInflater.from(activity)
            .inflate(R.layout.item_action_row, parent, false)

        val label = row.findViewById<TextView>(R.id.action_label)
        val icon = row.findViewById<ImageView>(R.id.action_icon)
        val emoji = row.findViewById<TextView>(R.id.action_emoji)

        label.text = item.label

        // 🔐 Разрушительное действие красится цветом ошибки: удаление
        // и отзыв ключей необратимы и не должны выглядеть так же,
        // как «копировать».
        if (item.destructive) {
            label.setTextColor(ContextCompat.getColor(activity, R.color.status_error))
            icon.setColorFilter(ContextCompat.getColor(activity, R.color.status_error))
        }

        when {
            item.emoji != null -> {
                emoji.text = item.emoji
                emoji.visibility = View.VISIBLE
                icon.visibility = View.GONE
            }

            item.icon != null -> icon.setImageResource(item.icon)

            // Пункт без значка: место под него сохраняется, чтобы
            // подписи не разъезжались по левому краю.
            else -> icon.visibility = View.INVISIBLE
        }

        row.setOnClickListener {
            dialog.dismiss()
            item.action()
        }

        return row
    }

    companion object {
        /** Насколько затемняется экран под панелью. */
        private const val DIM_AMOUNT = 0.6f

        /** Начинает сборку панели. */
        fun on(activity: Activity, title: String = ""): AegisSheet = AegisSheet(activity, title)

        /** Начинает сборку панели с заголовком из ресурсов. */
        fun on(activity: Activity, titleRes: Int): AegisSheet =
            AegisSheet(activity, activity.getString(titleRes))
    }
}

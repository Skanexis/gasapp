// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.FrameLayout
import android.widget.TextView
import androidx.annotation.StringRes
import org.gasapp.app.R
import org.gasapp.app.core.SecureWindow
import kotlin.math.min

/**
 * Диалог дизайн-системы GasApp (UI kit, слайд 20).
 *
 * Карточка не шире 340dp, заголовок H4, текст вторичного цвета, действия
 * справа: основное — кнопкой с заливкой, отказ — текстом. Опасное
 * действие — красной кнопкой ([Tone.Danger]): красный в GasApp означает
 * только ошибку или необратимое (раздел 20.1).
 *
 * # Почему свой диалог, а не AlertDialog
 *
 * Системный диалог рисует кнопки буквами вразрядку и без заливки,
 * а поле ввода ставит впритык к краям окна. Тема это исправляет лишь
 * отчасти и по-разному для платформенного и AppCompat-диалога — в
 * приложении были оба. Здесь раскладка одна, из токенов kit.
 *
 * # 🔐 Запрет снимков
 *
 * Диалог — отдельное окно, и `FLAG_SECURE` экрана на него не переходит.
 * [show] ставит флаг до показа (см. [SecureWindow.inherit]); диалоги,
 * где вводится ключ восстановления или PIN, — всегда ([alwaysSecure]).
 */
class GasAppDialog(private val host: Activity) {

    /** Вес основного действия. */
    enum class Tone {
        /** Обычное действие. */
        Accent,

        /** Необратимое действие: удаление, стирание. */
        Danger,
    }

    /** Показанный диалог: закрыть, показать ошибку, занять кнопку. */
    class Shown internal constructor(
        val dialog: Dialog,
        private val error: TextView,
        private val primaryButton: GasAppButton,
    ) {
        /** Показывает ошибку; диалог остаётся открытым. */
        fun showError(text: CharSequence) {
            error.text = text
            error.visibility = View.VISIBLE
        }

        /** Прячет ошибку — например, когда ввод исправлен. */
        fun clearError() {
            error.visibility = View.GONE
        }

        /**
         * Основное действие выполняется: кнопка недоступна и показывает
         * загрузку, повторное нажатие не запустит его второй раз.
         */
        fun setBusy(busy: Boolean) {
            primaryButton.isLoading = busy
        }

        /** Показывает ошибку из ресурсов. */
        fun showError(@StringRes text: Int) = showError(error.context.getString(text))

        /** Закрывает диалог и прячет клавиатуру, открытую для его поля. */
        fun dismiss() {
            hideKeyboard(dialog)
            dialog.dismiss()
        }
    }

    private class Action(
        val label: CharSequence,
        val tone: Tone,
        val closeOnClick: Boolean,
        val onClick: (Shown) -> Unit,
    )

    private var title: CharSequence? = null
    private var message: CharSequence? = null
    private var content: View? = null
    private var primary: Action? = null
    private var secondary: Action? = null
    private var secure = false
    private var cancelable = true
    private var onDismiss: (() -> Unit)? = null

    fun title(@StringRes text: Int) = apply { title = host.getString(text) }

    fun title(text: CharSequence) = apply { title = text }

    fun message(@StringRes text: Int) = apply { message = host.getString(text) }

    fun message(text: CharSequence) = apply { message = text }

    /** Содержимое под текстом: поле ввода, клавиатура PIN. */
    fun content(view: View) = apply { content = view }

    /**
     * Основное действие.
     *
     * @param closeOnClick `false` — диалог остаётся открытым, пока
     *   обработчик сам не вызовет [Shown.dismiss]: так поле ввода
     *   показывает ошибку, не теряя набранного.
     */
    fun primary(
        @StringRes label: Int,
        tone: Tone = Tone.Accent,
        closeOnClick: Boolean = true,
        onClick: (Shown) -> Unit = {},
    ) = apply { primary = Action(host.getString(label), tone, closeOnClick, onClick) }

    /** Отказ: текстовая кнопка слева от основной. */
    fun secondary(
        @StringRes label: Int = R.string.action_cancel,
        onClick: () -> Unit = {},
    ) = apply { secondary = Action(host.getString(label), Tone.Accent, true) { onClick() } }

    /** 🔐 Запрет снимков независимо от настройки — для PIN и ключей. */
    fun alwaysSecure() = apply { secure = true }

    fun cancelable(value: Boolean) = apply { cancelable = value }

    fun onDismiss(block: () -> Unit) = apply { onDismiss = block }

    /** Собирает и показывает диалог. */
    fun show(): Shown {
        val root = LayoutInflater.from(host).inflate(R.layout.view_dialog, null)
        val dialog = Dialog(host, R.style.GasAppDialogWindow)
        val shown = Shown(dialog, root.findViewById(R.id.dialog_error), root.findViewById(R.id.dialog_primary))

        root.findViewById<TextView>(R.id.dialog_title).apply {
            text = title
            visibility = if (title == null) View.GONE else View.VISIBLE
        }

        root.findViewById<TextView>(R.id.dialog_message).apply {
            text = message
            visibility = if (message == null) View.GONE else View.VISIBLE
        }

        content?.let { view ->
            (view.parent as? ViewGroup)?.removeView(view)
            root.findViewById<FrameLayout>(R.id.dialog_content).apply {
                addView(view, FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT)
                visibility = View.VISIBLE
            }
        }

        bind(root.findViewById(R.id.dialog_primary), primary, shown)
        bind(root.findViewById(R.id.dialog_secondary), secondary, shown)

        dialog.setContentView(root)
        dialog.setCancelable(cancelable)
        title?.let(dialog::setTitle)
        // Закрытие «Назад» или касанием мимо тоже прячет клавиатуру:
        // иначе она оставалась поверх экрана, где вводить уже нечего.
        dialog.setOnCancelListener { hideKeyboard(dialog) }
        onDismiss?.let { block -> dialog.setOnDismissListener { block() } }

        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

            // Не шире 340dp (UI kit) и с полями 24dp у краёв экрана.
            val metrics = host.resources.displayMetrics
            val margin = host.resources.getDimensionPixelSize(R.dimen.space_l)
            val maxWidth = host.resources.getDimensionPixelSize(R.dimen.dialog_max_width)
            setLayout(min(maxWidth, metrics.widthPixels - 2 * margin), ViewGroup.LayoutParams.WRAP_CONTENT)

            // С полем ввода клавиатура появляется сразу и не закрывает кнопки.
            if (content != null) {
                setSoftInputMode(
                    WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE or
                        WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE,
                )
            }
        }

        if (secure) SecureWindow.always(dialog) else SecureWindow.inherit(dialog, host)

        dialog.show()

        return shown
    }

    private companion object {
        fun hideKeyboard(dialog: Dialog) {
            val window = dialog.window ?: return
            val imm = window.context.getSystemService(InputMethodManager::class.java) ?: return
            imm.hideSoftInputFromWindow(window.decorView.windowToken, 0)
        }
    }

    private fun bind(button: GasAppButton, action: Action?, shown: Shown) {
        if (action == null) return

        button.text = action.label
        button.variant = when {
            button.id == R.id.dialog_secondary -> GasAppButton.Variant.Ghost
            action.tone == Tone.Danger -> GasAppButton.Variant.Danger
            else -> GasAppButton.Variant.Primary
        }
        button.visibility = View.VISIBLE
        button.setOnClickListener {
            if (action.closeOnClick) shown.dismiss()
            action.onClick(shown)
        }
    }
}

// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.app.Activity
import android.view.LayoutInflater
import androidx.annotation.StringRes
import androidx.core.widget.doAfterTextChanged
import org.gasapp.app.R
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppTextField

/**
 * Диалог названия и описания канала — один на создание и на правку.
 *
 * Правила длины — ядра (64 знака названия, 500 описания): поля лишь
 * не дают набрать больше. Пустое название отвергается здесь же, до
 * сети: ошибка стоит в диалоге, набранное не теряется.
 */
object ChannelForm {

    fun show(
        activity: Activity,
        @StringRes title: Int,
        @StringRes action: Int,
        @StringRes message: Int? = null,
        initialTitle: String = "",
        initialDescription: String = "",
        onSubmit: (title: String, description: String, dialog: GasAppDialog.Shown) -> Unit,
    ) {
        val form = LayoutInflater.from(activity).inflate(R.layout.view_channel_form, null)
        val name = form.findViewById<GasAppTextField>(R.id.channel_form_title)
        val description = form.findViewById<GasAppTextField>(R.id.channel_form_description)

        name.setText(initialTitle)
        description.setText(initialDescription)
        name.setSelection(name.text?.length ?: 0)

        val builder = GasAppDialog(activity)
            .title(title)
            .content(form)
            .secondary()
            .primary(action, closeOnClick = false) { dialog ->
                val entered = name.text?.toString().orEmpty().trim()

                if (entered.isEmpty()) {
                    name.hasError = true
                    dialog.showError(R.string.channel_form_title_empty)
                    return@primary
                }

                onSubmit(entered, description.text?.toString().orEmpty().trim(), dialog)
            }

        message?.let(builder::message)

        val shown = builder.show()

        name.doAfterTextChanged {
            if (name.hasError) {
                name.hasError = false
                shown.clearError()
            }
        }
        name.requestFocus()
    }
}

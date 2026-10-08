// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.text.InputType
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.R
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppSheet
import org.gasapp.app.components.GasAppTextField
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureClipboard
import uniffi.gasapp.FfiException

/**
 * Боты владельца: список, создание, удаление.
 *
 * # Что такое бот здесь
 *
 * Отдельный аккаунт, который ведёт программа владельца (`gasapp-bot`).
 * Приложение за бота ничего не делает и ключей его не видит: оно берёт
 * у сервера одноразовый токен, а владелец переносит его туда, где бот
 * будет работать.
 *
 * 🔐 Токен показывается один раз и на устройстве не сохраняется; в
 * буфер он уходит через защищённое копирование. Диалог с токеном
 * закрыт от снимков экрана независимо от настройки.
 *
 * @param explainPremium показать, почему ботов завести нельзя.
 */
class BotsPanel(
    private val activity: AppCompatActivity,
    private val explainPremium: () -> Unit,
) {

    /** Список ботов и пункт «Создать». */
    fun show() {
        activity.lifecycleScope.launch {
            io { Core.messenger().bots(now()) }
                .onSuccess { bots ->
                    val sheet = GasAppSheet.on(activity, R.string.bots_title)

                    sheet.action(activity.getString(R.string.bots_create), R.drawable.ic_plus) { promptCreate() }

                    for (bot in bots) {
                        sheet.action(activity.getString(R.string.bots_row, bot), R.drawable.ic_key) {
                            confirmDelete(bot)
                        }
                    }

                    sheet.show()
                }
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    private fun promptCreate() {
        val field = GasAppTextField(activity).apply {
            hint = activity.getString(R.string.bots_name_hint)
            maxLines = 1
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }

        GasAppDialog(activity)
            .title(R.string.bots_create)
            .message(R.string.bots_help)
            .content(field)
            .secondary()
            .primary(R.string.bots_create_action, closeOnClick = false) { dialog ->
                val name = field.text?.toString().orEmpty().trim().removePrefix("@")

                // Точное правило — у ядра и сервера; здесь только то, что
                // видно сразу.
                if (!name.lowercase().endsWith(BOT_SUFFIX) || name.length <= BOT_SUFFIX.length) {
                    field.hasError = true
                    dialog.showError(R.string.bots_name_invalid)
                    return@primary
                }

                dialog.setBusy(true)

                activity.lifecycleScope.launch {
                    val issued = io { Core.messenger().createBot(name, now()) }

                    dialog.setBusy(false)

                    issued
                        .onSuccess { token ->
                            dialog.dismiss()
                            showToken(name.lowercase(), token)
                        }
                        .onFailure { failure ->
                            when (failure) {
                                is FfiException.PremiumRequired -> {
                                    dialog.dismiss()
                                    explainPremium()
                                }
                                is FfiException.UsernameTaken -> dialog.showError(R.string.bots_name_taken)
                                is FfiException.InvalidArgument -> dialog.showError(R.string.bots_name_invalid)
                                else -> dialog.showError(R.string.bots_error_network)
                            }
                        }
                }
            }
            .show()
    }

    /** 🔐 Токен: один раз, без снимков экрана, копирование — защищённое. */
    private fun showToken(name: String, token: String) {
        GasAppDialog(activity)
            .title(activity.getString(R.string.bots_token_title, name))
            .message(activity.getString(R.string.bots_token_body, token))
            .alwaysSecure()
            .cancelable(false)
            .secondary(R.string.action_close)
            .primary(R.string.bots_token_copy, closeOnClick = false) {
                SecureClipboard.copySensitive(activity, activity.getString(R.string.bots_title), token)
                if (!SecureClipboard.systemConfirmsCopy) {
                    toast(R.string.bots_token_copied, GasAppToast.Tone.Success)
                }
            }
            .show()
    }

    private fun confirmDelete(bot: String) {
        GasAppDialog(activity)
            .title(activity.getString(R.string.bots_delete_title, bot))
            .message(R.string.bots_delete_body)
            .secondary()
            .primary(R.string.bots_delete_action, GasAppDialog.Tone.Danger, closeOnClick = false) { dialog ->
                dialog.setBusy(true)

                activity.lifecycleScope.launch {
                    val deleted = io { Core.messenger().deleteBot(bot, now()) }

                    dialog.setBusy(false)

                    deleted
                        .onSuccess {
                            dialog.dismiss()
                            toast(R.string.bots_deleted, GasAppToast.Tone.Success)
                        }
                        .onFailure { dialog.showError(R.string.channels_error_network) }
                }
            }
            .show()
    }

    private suspend fun <T> io(block: () -> T): Result<T> = withContext(Dispatchers.IO) { runCatching(block) }

    private fun now(): Long = System.currentTimeMillis()

    private fun toast(text: Int, tone: GasAppToast.Tone) = GasAppToast.show(activity, text, tone)

    private companion object {
        /** Чем кончается имя бота. */
        const val BOT_SUFFIX = "bot"
    }
}

// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.R
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppSheet
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureClipboard
import uniffi.gasapp.FfiChannel
import uniffi.gasapp.FfiChannelJoinRequest
import uniffi.gasapp.FfiChannelMember
import uniffi.gasapp.FfiException

/**
 * Закрытый канал глазами того, кто его ведёт: закрыть и открыть,
 * ссылки-приглашения, заявки на вход, подписчики и удалённые.
 *
 * # Что здесь важно сказать человеку — и когда
 *
 * * 🔐 Одобрить заявку — значит отдать ключ чтения канала. Забрать его
 *   обратно нельзя, поэтому диалог говорит это **до** кнопки и отдельно
 *   отмечает, знаком ли заявитель этому телефону или о нём известно
 *   только со слов сервера.
 * * 🔐 Удаление подписчика меняет ключ канала. Чего это не отменяет
 *   (прочитанного раньше) — сказано в подтверждении; если сменить ключ
 *   не вышло из-за связи — сказано сразу после.
 *
 * Криптографии здесь нет: экран показывает то, что подготовило ядро.
 *
 * @param reload перечитать канал после изменения.
 */
class ChannelGate(
    private val activity: AppCompatActivity,
    private val channelId: String,
    private val reload: () -> Unit,
) {

    /** Закрыть канал либо снова открыть — после подтверждения. */
    fun confirmClosed(current: FfiChannel) {
        val closing = !current.closed

        // Канал с @именем закрытым не бывает: по имени сервер отдаёт
        // ссылку с ключом чтения.
        if (closing && current.handle != null) {
            GasAppDialog(activity)
                .title(R.string.channel_close_title)
                .message(R.string.channel_close_has_handle)
                .primary(R.string.action_ok)
                .show()
            return
        }

        GasAppDialog(activity)
            .title(if (closing) R.string.channel_close_title else R.string.channel_open_title)
            .message(if (closing) R.string.channel_close_body else R.string.channel_open_body)
            .secondary()
            .primary(
                if (closing) R.string.channel_close_action else R.string.channel_open_action,
                closeOnClick = false,
            ) { dialog ->
                dialog.setBusy(true)

                activity.lifecycleScope.launch {
                    val done = io { Core.messenger().setChannelClosed(channelId, closing, now()) }

                    dialog.setBusy(false)

                    done
                        .onSuccess {
                            dialog.dismiss()
                            reload()
                        }
                        .onFailure { dialog.showError(R.string.channels_error_network) }
                }
            }
            .show()
    }

    /** Ссылки-приглашения: завести новую, скопировать, отозвать. */
    fun showInvites() {
        activity.lifecycleScope.launch {
            val invites = io { Core.messenger().channelInvites(channelId) }.getOrDefault(emptyList())
            val sheet = GasAppSheet.on(activity, R.string.channel_invites)

            sheet.action(activity.getString(R.string.channel_invite_create), R.drawable.ic_plus) { createInvite() }

            for (invite in invites) {
                sheet.action(
                    activity.getString(R.string.channel_invite_row, invite.takeLast(INVITE_HINT_CHARS)),
                    R.drawable.ic_link,
                ) { showInvite(invite) }
            }

            sheet.show()
        }
    }

    private fun createInvite() {
        activity.lifecycleScope.launch {
            io { Core.messenger().createChannelInvite(channelId, now()) }
                .onSuccess(::showInvite)
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    /**
     * Одна ссылка: что она даёт, копирование и отзыв.
     *
     * Ссылка секрета не несёт, но копируется через защищённый буфер,
     * как и всё, чем делятся из канала: в буфере она живёт недолго.
     */
    private fun showInvite(invite: String) {
        GasAppDialog(activity)
            .title(R.string.channel_invites)
            .message(activity.getString(R.string.channel_invite_body, invite))
            .secondary(R.string.channel_invite_revoke) { revokeInvite(invite) }
            .primary(R.string.channel_invite_copy) {
                SecureClipboard.copySensitive(activity, activity.getString(R.string.channel_invites), invite)
                if (!SecureClipboard.systemConfirmsCopy) {
                    toast(R.string.channel_invite_copied, GasAppToast.Tone.Success)
                }
            }
            .show()
    }

    private fun revokeInvite(invite: String) {
        activity.lifecycleScope.launch {
            io { Core.messenger().revokeChannelInvite(channelId, invite, now()) }
                .onSuccess { toast(R.string.channel_invite_revoked, GasAppToast.Tone.Success) }
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    /** Заявки, ждущие ответа. */
    fun showRequests() {
        activity.lifecycleScope.launch {
            io { Core.messenger().channelJoinRequests(channelId, now()) }
                .onSuccess { requests ->
                    if (requests.isEmpty()) {
                        toast(R.string.channel_requests_empty, GasAppToast.Tone.Info)
                        return@onSuccess
                    }

                    val sheet = GasAppSheet.on(activity, R.string.channel_requests)

                    for (request in requests) {
                        sheet.action(
                            activity.getString(
                                when {
                                    request.knownContact -> R.string.channel_request_row_known
                                    request.inKeyLog -> R.string.channel_request_row_key_log
                                    else -> R.string.channel_request_row
                                },
                                request.username,
                            ),
                            if (request.knownContact || request.inKeyLog) {
                                R.drawable.ic_shield_check
                            } else {
                                R.drawable.ic_users
                            },
                        ) { answer(request) }
                    }

                    sheet.show()
                }
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    /**
     * Ответ на заявку.
     *
     * 🔐 Что получает одобренный и откуда известно, кто он, — до кнопки.
     */
    private fun answer(request: FfiChannelJoinRequest) {
        GasAppDialog(activity)
            .title(activity.getString(R.string.channel_request_title, request.username))
            .message(
                when {
                    request.knownContact -> R.string.channel_request_body_known
                    request.inKeyLog -> R.string.channel_request_body_key_log
                    else -> R.string.channel_request_body_unknown
                },
            )
            .secondary(R.string.channel_request_decline) { send(request, approve = false) }
            .primary(R.string.channel_request_approve) { send(request, approve = true) }
            .show()
    }

    private fun send(request: FfiChannelJoinRequest, approve: Boolean) {
        activity.lifecycleScope.launch {
            io { Core.messenger().answerChannelJoin(channelId, request.accountId, approve, now()) }
                .onSuccess {
                    toast(
                        if (approve) R.string.channel_request_approved else R.string.channel_request_declined,
                        GasAppToast.Tone.Success,
                    )
                    reload()
                    // Остальные заявки — сразу: их обычно разбирают подряд.
                    showRequests()
                }
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    /** Подписчики — страницами, от начала либо после аккаунта [after]. */
    fun showSubscribers(after: String? = null) {
        activity.lifecycleScope.launch {
            io { Core.messenger().channelSubscribers(channelId, after, now()) }
                .onSuccess { members ->
                    if (members.isEmpty()) {
                        toast(R.string.channel_members_empty, GasAppToast.Tone.Info)
                        return@onSuccess
                    }

                    val sheet = GasAppSheet.on(activity, R.string.channel_members)

                    for (member in members) {
                        sheet.action(nameOf(member), R.drawable.ic_users) { confirmRemove(member) }
                    }

                    // Полная страница — возможно, не последняя.
                    if (members.size >= PAGE) {
                        sheet.action(activity.getString(R.string.channel_members_more), R.drawable.ic_plus) {
                            showSubscribers(after = members.last().accountId)
                        }
                    }

                    sheet.action(activity.getString(R.string.channel_banned), R.drawable.ic_block) { showBanned() }
                    sheet.show()
                }
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    /** ⚠️ Чего удаление не даёт, сказано до кнопки. */
    private fun confirmRemove(member: FfiChannelMember) {
        GasAppDialog(activity)
            .title(activity.getString(R.string.channel_member_remove_title, nameOf(member)))
            .message(R.string.channel_member_remove_body)
            .secondary()
            .primary(R.string.channel_member_remove, GasAppDialog.Tone.Danger, closeOnClick = false) { dialog ->
                dialog.setBusy(true)

                activity.lifecycleScope.launch {
                    val removed = io {
                        Core.messenger().removeChannelSubscriber(channelId, member.accountId, false, now())
                    }

                    dialog.setBusy(false)

                    removed
                        .onSuccess {
                            dialog.dismiss()

                            // 🔐 Ключ канала после удаления меняется. Не
                            // вышло (нет связи) — человек должен это знать.
                            val pending = io { Core.messenger().channel(channelId).rekeyPending }
                                .getOrDefault(false)
                            if (pending) {
                                toast(R.string.channel_member_removed_rekey_pending, GasAppToast.Tone.Info)
                            } else {
                                toast(R.string.channel_member_removed, GasAppToast.Tone.Success)
                            }
                            reload()
                        }
                        .onFailure { failure ->
                            dialog.showError(
                                if (failure is FfiException.InvalidArgument) {
                                    R.string.channel_member_is_admin
                                } else {
                                    R.string.channels_error_network
                                },
                            )
                        }
                }
            }
            .show()
    }

    /** Удалённые из канала: кому можно вернуть право подать заявку. */
    private fun showBanned() {
        activity.lifecycleScope.launch {
            io { Core.messenger().channelBanned(channelId, now()) }
                .onSuccess { banned ->
                    if (banned.isEmpty()) {
                        toast(R.string.channel_banned_empty, GasAppToast.Tone.Info)
                        return@onSuccess
                    }

                    val sheet = GasAppSheet.on(activity, R.string.channel_banned)

                    for (member in banned) {
                        sheet.action(nameOf(member), R.drawable.ic_block) { confirmRestore(member) }
                    }

                    sheet.show()
                }
                .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
        }
    }

    private fun confirmRestore(member: FfiChannelMember) {
        GasAppDialog(activity)
            .title(activity.getString(R.string.channel_banned_restore_title, nameOf(member)))
            .message(R.string.channel_banned_restore_body)
            .secondary()
            .primary(R.string.channel_banned_restore_action) {
                activity.lifecycleScope.launch {
                    io { Core.messenger().removeChannelSubscriber(channelId, member.accountId, true, now()) }
                        .onSuccess { toast(R.string.channel_banned_restored, GasAppToast.Tone.Success) }
                        .onFailure { toast(R.string.channels_error_network, GasAppToast.Tone.Error) }
                }
            }
            .show()
    }

    /** Имя — со слов сервера; если он назвал не имя, остаётся аккаунт. */
    private fun nameOf(member: FfiChannelMember): String =
        if (member.username.isNotEmpty()) {
            activity.getString(R.string.channel_request_row, member.username)
        } else {
            activity.getString(R.string.channel_member_unnamed, member.accountId.take(ACCOUNT_HINT_CHARS))
        }

    private suspend fun <T> io(block: () -> T): Result<T> = withContext(Dispatchers.IO) { runCatching(block) }

    private fun now(): Long = System.currentTimeMillis()

    private fun toast(text: Int, tone: GasAppToast.Tone) = GasAppToast.show(activity, text, tone)

    private companion object {
        /** Сколько последних знаков ссылки показывает список. */
        const val INVITE_HINT_CHARS = 8

        /** Сколько первых знаков аккаунта показывается вместо имени. */
        const val ACCOUNT_HINT_CHARS = 8

        /** Страница подписчиков на сервере. */
        const val PAGE = 100
    }
}

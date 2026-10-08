// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.app.Activity
import android.content.Intent
import android.os.SystemClock
import androidx.annotation.StringRes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.OnboardingActivity
import org.gasapp.app.R
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.components.PinPad

/**
 * 🔐 Повторный PIN перед действиями, которые нельзя отдать тому, кому
 * достался разблокированный телефон (аудит 2026-10-02, A-3).
 *
 * # Что было
 *
 * Открытое приложение не спрашивало PIN ни для чего. За полминуты
 * с чужим разблокированным телефоном можно было:
 *
 * * выгрузить всю переписку открытым текстом в «Загрузки» или облако;
 * * создать **новый** ключ восстановления, увидеть его на экране и
 *   сохранить копию куда угодно — а с копией и ключом восстановить
 *   аккаунт на своём телефоне: копия несёт ключ перепривязки аккаунта,
 *   и сервер переводит имя на новое устройство;
 * * удалить аккаунт;
 * * тихо ослабить защиту: выключить стирание после десяти неверных PIN,
 *   запрет снимков экрана, Tor; растянуть автоблокировку.
 *
 * # Как устроено
 *
 * [require] спрашивает PIN своей клавиатурой в защищённом окне и
 * проверяет его через [PinCheck] — с общим счётом попыток, задержками и
 * стиранием. Успех открывает окно в [GRACE_MILLIS], чтобы цепочка
 * действий («создать ключ → сделать копию») не спрашивала PIN дважды.
 * Окно закрывается при запирании приложения ([forget]).
 *
 * Отпечаток здесь намеренно не принимается: палец прикладывают и
 * против воли, а действия за этой дверью необратимы.
 */
object Reauth {

    /** Сколько живёт подтверждение. */
    const val GRACE_MILLIS = 60_000L

    /** Когда PIN подтверждён (`elapsedRealtime`); 0 — не подтверждён. */
    @Volatile
    private var confirmedAt = 0L

    /** Подтверждён ли PIN только что. */
    fun isFresh(): Boolean {
        val at = confirmedAt
        return at != 0L && SystemClock.elapsedRealtime() - at in 0 until GRACE_MILLIS
    }

    /** 🔐 Забывает подтверждение — при запирании приложения. */
    fun forget() {
        confirmedAt = 0L
    }

    /**
     * Выполняет [action] после верного PIN.
     *
     * Неверный PIN, отказ или идущая задержка — [action] не выполняется.
     */
    fun require(activity: Activity, @StringRes reason: Int, action: () -> Unit) {
        if (!Core.isUnlocked) {
            return
        }

        if (isFresh()) {
            action()
            return
        }

        val waiting = PinAttempts.remainingMillis(activity)
        if (waiting > 0L) {
            GasAppToast.show(activity, PinCheck.waitText(activity, waiting), GasAppToast.Tone.Warning)
            return
        }

        val view = activity.layoutInflater.inflate(R.layout.dialog_pin, null)
        var dialog: GasAppDialog.Shown? = null

        PinPad(view) { pad ->
            val pin = pad.take()
            pad.setEnabled(false)
            dialog?.setBusy(true)

            AppScope.launch {
                val outcome = withContext(Dispatchers.IO) { PinCheck.verify(activity, pin) }
                val shown = dialog

                if (outcome is PinCheck.Outcome.Correct) {
                    confirmedAt = SystemClock.elapsedRealtime()
                }

                if (activity.isFinishing || activity.isDestroyed) {
                    return@launch
                }

                shown?.setBusy(false)

                when (outcome) {
                    PinCheck.Outcome.Correct -> {
                        shown?.dismiss()
                        action()
                    }

                    is PinCheck.Outcome.Wrong -> {
                        pad.showWrong()
                        if (outcome.waitMillis > 0L) {
                            shown?.dismiss()
                            GasAppToast.show(activity, R.string.lock_error_wait, GasAppToast.Tone.Warning)
                        } else {
                            pad.setEnabled(true)
                            shown?.showError(R.string.lock_error_wrong)
                        }
                    }

                    is PinCheck.Outcome.Wait -> {
                        shown?.dismiss()
                        GasAppToast.show(activity, PinCheck.waitText(activity, outcome.millis), GasAppToast.Tone.Warning)
                    }

                    PinCheck.Outcome.Wiped -> {
                        shown?.dismiss()
                        activity.startActivity(
                            Intent(activity, OnboardingActivity::class.java)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                        )
                        activity.finish()
                    }
                }
            }
        }

        dialog = GasAppDialog(activity)
            .title(reason)
            .message(R.string.reauth_body)
            .content(view)
            .secondary()
            .alwaysSecure()
            .show()
    }
}

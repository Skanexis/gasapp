// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.app.Activity
import org.gasapp.app.R
import org.gasapp.app.components.GasAppDialog

/**
 * 🔐 Предупреждение о пересобранной копии — до ввода PIN.
 *
 * [AppSignature] раньше смотрели только в Центре безопасности, то есть
 * там, куда жертва поддельного APK не заглянет: PIN и переписку она
 * отдаёт копии раньше. Теперь проверка — на каждом запуске экрана входа
 * и регистрации, и несовпадение подписи останавливает человека до того,
 * как он что-то ввёл.
 *
 * Выбор оставлен человеку: закрыть или продолжить. Запретить работу
 * совсем бессмысленно — пересобравший вырежет и сам запрет, — а
 * честный собиратель из исходников получает свою подпись в эталон
 * (`app/build.gradle`) и этого окна не видит вовсе.
 *
 * ⚠️ Целенаправленная подделка вырежет и эту проверку. Главная защита
 * от подмены сборки — канал установки и воспроизводимая сборка
 * (`docs/ops/reproducible-builds.md`); это окно ловит бесхитростную
 * пересборку, которой распространяют «взломанные» копии.
 */
object TamperGuard {

    /** Показано ли уже в этом процессе: не повторять на каждом экране. */
    @Volatile
    private var acknowledged = false

    /**
     * Проверяет подпись установленного APK и при несовпадении показывает
     * предупреждение. Отладочная сборка эталона не имеет и не проверяется.
     */
    fun warnIfForged(activity: Activity) {
        if (acknowledged) return

        val verdict = runCatching { AppSignature.check(activity, attested = null) }
            .getOrDefault(AppSignature.Verdict.MISMATCH)

        if (verdict != AppSignature.Verdict.MISMATCH) return

        GasAppDialog(activity)
            .title(R.string.tamper_title)
            .message(R.string.tamper_body)
            .alwaysSecure()
            .cancelable(false)
            .secondary(R.string.tamper_continue) { acknowledged = true }
            .primary(R.string.tamper_close, GasAppDialog.Tone.Danger) { activity.finishAffinity() }
            .show()
    }
}

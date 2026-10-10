// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.app.Activity
import android.content.Intent
import android.net.Uri
import org.gasapp.app.BuildConfig
import org.gasapp.app.R
import org.gasapp.app.components.GasAppSheet
import org.gasapp.app.components.GasAppToast

/**
 * Документы, которые человек вправе прочитать до и после регистрации:
 * условия использования, политика конфиденциальности, правила
 * сообщества, безопасность детей, удаление аккаунта, поддержка.
 *
 * Страницы лежат на сайте проекта (`tools/build-site.py`), адрес сайта
 * задаётся сборкой. Открываются они в браузере человека: встроенного
 * веб-просмотра в приложении нет намеренно — меньше кода, которому
 * нужно доверять.
 *
 * 🔐 Переход по ссылке — выход из приложения в браузер: сайт видит
 * IP-адрес, даже если переписка идёт через Tor. Поэтому список
 * открывается по нажатию, а не сам.
 */
object Legal {

    enum class Page(val path: String, val title: Int) {
        Terms("terms/", R.string.legal_terms),
        Privacy("privacy/", R.string.legal_privacy),
        Guidelines("community-guidelines/", R.string.legal_guidelines),
        ChildSafety("child-safety/", R.string.legal_child_safety),
        AccountDeletion("account-deletion/", R.string.legal_account_deletion),
        Support("support/", R.string.legal_support),
    }

    /** Список документов; нажатие открывает страницу в браузере. */
    fun show(activity: Activity, pages: List<Page> = Page.entries) {
        val sheet = GasAppSheet.on(activity, R.string.legal_title)

        for (page in pages) {
            sheet.action(activity.getString(page.title), R.drawable.ic_file) { open(activity, page) }
        }

        sheet.show()
    }

    fun open(activity: Activity, page: Page) {
        val address = BuildConfig.GASAPP_DOCS_URL.trimEnd('/') + "/" + page.path

        runCatching { activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(address))) }
            .onFailure { GasAppToast.show(activity, R.string.legal_open_failed, GasAppToast.Tone.Error) }
    }
}

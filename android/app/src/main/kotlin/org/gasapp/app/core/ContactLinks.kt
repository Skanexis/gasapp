// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

/**
 * Ссылка на контакт в двух видах — как `ContactLinks` на iPhone.
 *
 * * `https://gasapp.eu/add/#KEY.PQ?name=…` — для людей: мессенджеры
 *   делают её кликабельной, а на iPhone она сразу открывает GasApp.
 *   Без приложения — страница сайта со ссылками на магазины.
 * * `gasapp://contact/KEY.PQ?name=…` — то, что разбирает ядро
 *   (`addContactFromLink`) и что лежит в QR.
 *
 * 🔐 Ключ стоит после `#`: эту часть адреса браузер на сервер не
 * отправляет.
 */
object ContactLinks {

    const val APP_PREFIX = "gasapp://contact/"

    const val WEB_PREFIX = "https://gasapp.eu/add/#"

    private val WEB_PAGES = setOf(
        "https://gasapp.eu/add/", "https://gasapp.eu/add",
        "https://www.gasapp.eu/add/", "https://www.gasapp.eu/add",
    )

    /** Любой вид ссылки → вид для ядра; `null` — это не ссылка на контакт. */
    fun appLink(text: String): String? {
        val trimmed = text.trim()
        if (trimmed.startsWith(APP_PREFIX, ignoreCase = true)) {
            return APP_PREFIX + trimmed.substring(APP_PREFIX.length)
        }
        val hash = trimmed.indexOf('#').takeIf { it >= 0 } ?: return null
        val page = trimmed.substring(0, hash).lowercase()
        val payload = trimmed.substring(hash + 1)

        return if (page in WEB_PAGES && payload.isNotEmpty()) APP_PREFIX + payload else null
    }

    /** Вид для ядра → вид для людей (кнопка «Поделиться»). */
    fun webLink(appLink: String): String =
        if (appLink.startsWith(APP_PREFIX)) WEB_PREFIX + appLink.substring(APP_PREFIX.length) else appLink
}

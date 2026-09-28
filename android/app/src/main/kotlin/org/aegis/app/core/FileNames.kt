// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

/**
 * 🔐 Имя файла от чужого приложения — безопасным для пути и для показа.
 *
 * Имена приходят из `DISPLAY_NAME` провайдера, из которого человек
 * выбрал файл, то есть от любого установленного приложения:
 *
 * * `../../databases/aegis.db` вывел бы запись за каталог (хранилище
 *   файлов, см. [VaultTemp.fileFor]);
 * * `счёт‮fdp.exe` показался бы «счётexe.pdf» — документом, а был
 *   бы исполняемым. Ядро такое имя во вложении отвергает, и файл
 *   не отправился бы вовсе.
 *
 * Остаётся последний сегмент пути без управляющих символов, символов
 * смены направления текста и точек по краям.
 */
object FileNames {

    /** Наибольшая длина: предел большинства файловых систем — 255 байт. */
    private const val MAX_CHARS = 120

    /** Имя, если от исходного ничего не осталось. */
    private const val FALLBACK = "file"

    fun safe(name: String): String {
        val lastSegment = name.substringAfterLast('/').substringAfterLast('\\')
        val cleaned = lastSegment
            .filterNot { it.isISOControl() || isBidiControl(it) }
            .trim()
            .trim('.')
            .take(MAX_CHARS)

        return cleaned.ifEmpty { FALLBACK }
    }

    /** Символы, меняющие направление текста (встраивание, переопределение, изоляция). */
    private fun isBidiControl(character: Char): Boolean =
        character in '‪'..'‮' || character in '⁦'..'⁩'
}

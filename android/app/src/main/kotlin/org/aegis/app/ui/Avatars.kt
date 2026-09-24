// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

/**
 * Инициалы для аватара.
 *
 * Берутся две буквы из разных слов, как в макете («Lena Novak» даёт
 * «LN»); у имени из одного слова — две первые буквы. Одна буква хуже
 * различает контакты в длинном списке.
 */
fun initialsOf(name: String): String {
    val parts = name.split(' ', '_').filter { it.isNotEmpty() }

    return when {
        parts.size >= 2 -> "${parts[0].first()}${parts[1].first()}".uppercase()
        parts.isNotEmpty() -> parts[0].take(2).uppercase()
        else -> "?"
    }
}

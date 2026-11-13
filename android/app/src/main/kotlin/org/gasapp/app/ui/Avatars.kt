// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import org.gasapp.app.R

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

/**
 * Краски аватаров: пастельные «типографские» тона на тёмной бумаге.
 *
 * Набор намеренно не пересекается со смыслом статусов: зелёного
 * («сверено»), красного и жёлтого («внимание») среди них нет — цвет
 * собеседника не должен читаться как состояние защиты.
 */
private val AVATAR_INKS = intArrayOf(
    0xFFFFCB2E.toInt(), // барвинок — краска приложения
    0xFF5ED3C9.toInt(), // морская волна
    0xFFF59AB8.toInt(), // роза
    0xFFF5B08A.toInt(), // абрикос
    0xFFC4A9FF.toInt(), // сирень
    0xFF7FC4F5.toInt(), // небо
)

/**
 * Красит аватар по имени собеседника: одно имя — всегда один цвет.
 *
 * Цвет помогает узнать собеседника в списке взглядом, но не заменяет
 * имя: оно рядом всегда.
 */
fun paintAvatar(avatar: android.widget.TextView, key: String) {
    val ink = AVATAR_INKS[Math.floorMod(key.hashCode(), AVATAR_INKS.size)]

    avatar.setTextColor(ink)

    // Свой круг заводится у вида один раз и дальше только перекрашивается:
    // строки списка привязываются при каждой прокрутке, и новый фон
    // на каждую — мусор для сборщика посреди кадра.
    val circle = avatar.getTag(R.id.chat_avatar) as? android.graphics.drawable.GradientDrawable
        ?: android.graphics.drawable.GradientDrawable().also {
            it.shape = android.graphics.drawable.GradientDrawable.OVAL
            avatar.setTag(R.id.chat_avatar, it)
        }

    if (avatar.background !== circle) avatar.background = circle

    circle.setColor(androidx.core.graphics.ColorUtils.setAlphaComponent(ink, AVATAR_FILL_ALPHA))
}

/** Подложка аватара — краска на ~16 %. */
private const val AVATAR_FILL_ALPHA = 0x29

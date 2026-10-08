// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import android.view.LayoutInflater
import android.widget.FrameLayout
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.R
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Каждая разметка раздувается.
 *
 * # Что здесь проверяется
 *
 * Семь экранов падали при открытии — File Vault, создание, подтверждение
 * и центр ключа восстановления, восстановление из копии, настройки сети,
 * экран смены ключа: у их `TextView` не было `layout_height`, а стиль его
 * не задавал. Открытие File Vault на эмуляторе роняло приложение целиком.
 *
 * Android Lint этого не видел (`RequiredSize` доверяет стилю, не проверяя
 * его), а Robolectric показывал то же исключение — и его приняли за
 * особенность стенда. Этот тест раздувает все разметки подряд: исключение
 * здесь — это исключение на телефоне.
 *
 * Размеры отдельно проверяет `tools/check-layout-sizes.py` — без Gradle.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EveryLayoutInflatesTest {

    @Test
    fun every_layout_inflates() {
        val context: Context = ApplicationProvider.getApplicationContext()
        context.setTheme(R.style.Theme_GasApp)

        val inflater = LayoutInflater.from(context)
        val parent = FrameLayout(context)

        val layouts = R.layout::class.java.fields
            .filter { it.type == Int::class.javaPrimitiveType }
            // Разметки библиотек (AndroidX, Material) — не наши.
            .filter { field ->
                val name = context.resources.getResourceEntryName(field.getInt(null))
                context.resources.getResourcePackageName(field.getInt(null)) == context.packageName &&
                    (name.startsWith("activity_") || name.startsWith("item_") || name.startsWith("view_"))
            }

        assertTrue("разметок не найдено — фильтр сломан", layouts.size >= MIN_LAYOUTS)

        val failures = layouts.mapNotNull { field ->
            runCatching { inflater.inflate(field.getInt(null), parent, false) }
                .exceptionOrNull()
                ?.let { "${field.name}: ${it.message?.lineSequence()?.firstOrNull()}" }
        }

        assertTrue(
            "не раздуваются — экран упадёт при открытии:\n" + failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    private companion object {
        const val MIN_LAYOUTS = 20
    }
}

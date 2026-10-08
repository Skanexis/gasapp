// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import androidx.appcompat.content.res.AppCompatResources
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.R
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Каждый drawable приложения загружается.
 *
 * # Что здесь проверяется
 *
 * Значок с испорченным `pathData` собирается без единого предупреждения:
 * aapt не разбирает пути векторов. Падает он только в момент показа —
 * так значок галочки под полем «Добавить контакт» ронял приложение
 * ровно при успешном добавлении контакта. Lint и сборка этого не видели.
 *
 * Здесь все drawable загружаются подряд, с настоящим разбором путей
 * (нативная графика Robolectric).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class EveryDrawableLoadsTest {

    @Test
    fun every_drawable_loads() {
        val context: Context = ApplicationProvider.getApplicationContext()
        context.setTheme(R.style.Theme_GasApp)

        val drawables = R.drawable::class.java.fields
            .filter { it.type == Int::class.javaPrimitiveType }
            .map { it.name to it.getInt(null) }
            // Только свои ресурсы, не библиотек.
            .filter { (_, id) -> context.resources.getResourcePackageName(id) == context.packageName }
            .filter { (name, _) -> name.startsWith("ic_") || name.startsWith("bg_") || name.startsWith("btn_") }

        assertTrue("drawable не найдены — фильтр сломан", drawables.size >= MIN_DRAWABLES)

        val failures = drawables.mapNotNull { (name, id) ->
            runCatching { requireNotNull(AppCompatResources.getDrawable(context, id)) }
                .exceptionOrNull()
                ?.let { "$name: ${it.cause?.message ?: it.message}" }
        }

        assertTrue("не загружаются — экран упадёт при показе:\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    private companion object {
        const val MIN_DRAWABLES = 40
    }
}

// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.view.WindowManager
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.Core
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 🔐 `FLAG_SECURE` стоит на каждом экране приложения — на настоящих окнах.
 *
 * # Что здесь проверяется
 *
 * MASVS STORAGE-2.5: содержимое экранов не попадает в снимки
 * переключателя задач. Прежде это было «проверено чтением»: каждый экран
 * вызывает `SecureWindow`, и автопроверки не было — без открытого
 * хранилища экраны переписки не открываются (их закрывает сторож
 * блокировки), а открыть его в модульном тесте нечем: нативной
 * библиотеки там нет.
 *
 * Здесь хранилище открывается по-настоящему: `Core.unlock` заводит
 * локальную базу под тестовым PIN — без сервера и без регистрации.
 * Затем открывается **каждая** activity из манифеста, а не список:
 * новый экран без `SecureWindow` провалит тест сам.
 *
 * ⚠️ На устройстве с настоящим аккаунтом тест пропускается: его PIN
 * неизвестен, а трогать чужую базу нельзя. После теста всё стирается
 * (`AccountWipe`).
 */
@RunWith(AndroidJUnit4::class)
class EveryScreenSecureOnDeviceTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun openAFreshStorage() {
        assumeFalse(
            "на устройстве есть настоящая база — её PIN неизвестен, трогать её нельзя",
            File(context.filesDir, "aegis.db").exists(),
        )

        Core.unlock(context, TEST_PIN.toByteArray())
    }

    @After
    fun wipeIt() {
        AccountWipe.wipe(context)
    }

    @Test
    fun every_screen_blocks_screenshots() {
        val activities = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_ACTIVITIES)
            .activities
            .orEmpty()
            .map { it.name }
            .filter { it.startsWith("org.aegis.app.") }

        assertTrue("заготовка теста: activity не найдены", activities.size > 10)

        val capturable = mutableListOf<String>()
        val readable = mutableListOf<String>()
        val opened = mutableListOf<String>()

        for (name in activities) {
            @Suppress("UNCHECKED_CAST")
            val type = Class.forName(name) as Class<Activity>

            ActivityScenario.launch(type).use { scenario ->
                // Экран без нужных ему данных (например, переписка без
                // идентификатора чата) вправе закрыться сразу — окна
                // тогда нет, и снимать нечего.
                if (scenario.state == Lifecycle.State.DESTROYED) {
                    return@use
                }

                scenario.onActivity { activity ->
                    opened += name.substringAfterLast('.')

                    val flags = activity.window.attributes.flags
                    if (flags and WindowManager.LayoutParams.FLAG_SECURE == 0) {
                        capturable += name.substringAfterLast('.')
                    }

                    // 🔐 Android 14+: содержимое окна — только инструментам
                    // доступности, не шпионским службам (SecureWindow).
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
                        !activity.window.decorView.isAccessibilityDataSensitive
                    ) {
                        readable += name.substringAfterLast('.')
                    }
                }
            }
        }

        assertTrue("заготовка теста: не открылся ни один экран", opened.size > 10)
        assertTrue(
            "экраны снимаются: $capturable (открыто ${opened.size}: $opened)",
            capturable.isEmpty(),
        )
        assertTrue(
            "экраны открыты службам специальных возможностей, не являющимся инструментами: $readable",
            readable.isEmpty(),
        )
    }

    private companion object {
        const val TEST_PIN = "135790"
    }
}

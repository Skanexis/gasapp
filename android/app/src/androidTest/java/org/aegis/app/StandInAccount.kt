// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.rules.ExternalResource

/**
 * Файл базы-заместитель, без которого экран входа уводит на регистрацию.
 *
 * Экран входа показывается, только если на устройстве есть база
 * (`LockActivity.hasAccount`). Тесты экрана не зависят от того, завёл ли
 * кто-то аккаунт на этом устройстве раньше: без правила они проходили
 * там, где аккаунт был, и падали на свежей установке — в том числе
 * в CI и после того, как прогон удалил приложение вместе с данными.
 *
 * Настоящую базу правило не трогает: если файл уже есть, он остаётся
 * как был, и после теста тоже. Полный PIN тесты не набирают, так что
 * открыть заместителя никто не пытается.
 */
class StandInAccount : ExternalResource() {
    private var created: File? = null

    override fun before() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = File(context.filesDir, "aegis.db")

        if (!database.exists()) {
            database.writeBytes(ByteArray(0))
            created = database
        }
    }

    override fun after() {
        created?.delete()
        created = null
    }
}

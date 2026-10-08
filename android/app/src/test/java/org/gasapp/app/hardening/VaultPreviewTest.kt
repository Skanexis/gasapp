// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import java.io.File
import org.gasapp.app.core.VaultTemp
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Нет превью файлов хранилища в системном кэше (MASVS STORAGE-2.6).
 *
 * # Откуда берутся превью
 *
 * Превью файла появляется в чужом кэше, когда файл оказывается
 * у системы или у другого приложения:
 *
 *  * `content://` через `FileProvider` — просмотрщик кладёт копию
 *    и миниатюру к себе, и вернуть их оттуда нельзя;
 *  * запись в `MediaStore` — галерея строит миниатюру сама;
 *  * расшифровка во внешнее хранилище — его видит любое приложение
 *    с доступом к файлам.
 *
 * Прежде строка чек-листа стояла 🟡 «проверено чтением». Здесь каждый
 * из трёх путей закрыт проверкой, которая краснеет, если путь откроют.
 *
 * # Чего тест не проверяет
 *
 * Исходник, из которого файл добавлен: он лежит в общей памяти до
 * добавления, и приложение может лишь предложить его удалить
 * (`VaultActivity.offerToDeleteOriginal`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultPreviewTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    /**
     * Ни один провайдер не раздаёт права на свои URI.
     *
     * `grantUriPermissions` — единственный способ отдать файл
     * приложения чужому приложению по `content://`. Провайдеры
     * библиотек (инициализация AndroidX) им не пользуются.
     */
    @Test
    fun no_provider_hands_out_file_uris() {
        @Suppress("DEPRECATION")
        val providers = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_PROVIDERS)
            .providers
            .orEmpty()

        val granting = providers.filter { it.grantUriPermissions || it.exported }.map { it.name }

        assertTrue("провайдеры раздают файлы наружу: $granting", granting.isEmpty())
    }

    /** Расшифрованная копия — во внутреннем кэше, не во внешнем хранилище. */
    @Test
    fun decrypted_copies_stay_in_private_storage() {
        val dir = VaultTemp.directory(context).canonicalFile
        val private = context.cacheDir.canonicalFile

        assertTrue(
            "каталог расшифрованных файлов вне внутреннего кэша: $dir",
            dir.path.startsWith(private.path + File.separator),
        )

        context.externalCacheDir?.canonicalFile?.let { external ->
            assertFalse("каталог во внешнем кэше", dir.path.startsWith(external.path))
        }
    }

    /**
     * Код приложения не пишет в медиатеку, не строит миниатюр
     * и не отдаёт файлы через `FileProvider`.
     *
     * Проверка по исходникам, а не по поведению: эти пути открываются
     * одной строкой в любом экране, и ловить их надо до того, как они
     * появятся, а не на устройстве после.
     */
    @Test
    fun no_code_path_creates_previews() {
        val sources = File("src/main/kotlin")
        assertTrue("заготовка теста: исходники не найдены из ${File(".").absolutePath}", sources.isDirectory)

        val forbidden = listOf(
            "MediaStore",
            "ThumbnailUtils",
            "loadThumbnail",
            "createVideoThumbnail",
            "FileProvider",
            "getExternalFilesDir",
            "externalCacheDir",
            "getExternalStoragePublicDirectory",
        )

        val hits = sources.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            // Сгенерированные биндинги ядра к файлам отношения не имеют.
            .filterNot { it.path.replace('\\', '/').contains("/uniffi/") }
            .flatMap { file ->
                file.readLines().mapIndexedNotNull { index, line ->
                    val code = line.substringBefore("//").trim()
                    val isComment = code.startsWith("*") || code.startsWith("/*")

                    forbidden.firstOrNull { !isComment && code.contains(it) }
                        ?.let { "${file.name}:${index + 1}: $it" }
                }
            }
            .toList()

        assertTrue("пути к превью в коде: $hits", hits.isEmpty())
    }
}

// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.util.LruCache
import android.widget.ImageView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.R
import org.gasapp.app.core.Core
import java.nio.ByteBuffer

/**
 * Картинки канала: скачать, расшифровать, показать.
 *
 * # 🔐 Что здесь важно
 *
 * * **Только память.** Расшифрованная картинка не пишется на диск: ни
 *   кеша, ни временного файла. Копия вне зашифрованной базы досталась
 *   бы системным бэкапам и любому, кто получит телефон. Кеш в памяти
 *   очищается, когда человек уходит с экрана ([clear]).
 * * **Картинку прислал автор канала**, а канал может быть чужим
 *   и недружественным. Декодирует её системный `ImageDecoder` —
 *   программно, без аппаратных буферов, — с уменьшением до размера
 *   экрана: картинка в сто мегапикселей не займёт память целиком.
 *   Любой сбой декодера — это просто «картинки нет».
 * * **Большие картинки сами не качаются** ([AUTO_LOAD_BYTES]): лента
 *   чужого канала не должна тратить трафик и память без спроса. Такая
 *   картинка показывается строкой файла, и её можно сохранить.
 * * Скачивание идёт без подписи устройства: сервер не знает, кто
 *   смотрит картинку (см. `gasapp_core::client::channels`).
 */
class ChannelImages(
    private val scope: CoroutineScope,
    private val channelId: String,
) {

    private val cache = object : LruCache<Int, Bitmap>(CACHE_BYTES) {
        override fun sizeOf(key: Int, value: Bitmap): Int = value.allocationByteCount
    }

    /** Описания, по которым картинку получить не удалось: второй раз не пробуем. */
    private val failed = HashSet<Int>()

    /**
     * Ставит в [view] картинку по описанию вложения: из памяти — сразу,
     * иначе скачивает и расшифровывает.
     *
     * [view] может быть переиспользован лентой, пока идёт загрузка:
     * результат ставится, только если вид всё ещё ждёт эту картинку.
     */
    fun into(descriptor: ByteArray, view: ImageView) {
        val key = descriptor.contentHashCode()
        view.setTag(R.id.channel_image_key, key)

        cache.get(key)?.let {
            view.setImageBitmap(it)
            return
        }

        view.setImageDrawable(null)
        if (key in failed) return

        scope.launch {
            val bitmap = withContext(Dispatchers.IO) {
                runCatching {
                    decode(Core.messenger().fetchChannelMedia(channelId, descriptor))
                }.getOrNull()
            }

            if (bitmap == null) {
                failed.add(key)
                return@launch
            }

            cache.put(key, bitmap)
            if (view.getTag(R.id.channel_image_key) == key) view.setImageBitmap(bitmap)
        }
    }

    /** 🔐 Стирает расшифрованные картинки из памяти. */
    fun clear() {
        cache.evictAll()
        failed.clear()
    }

    private fun decode(bytes: ByteArray): Bitmap =
        ImageDecoder.decodeBitmap(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) { decoder, info, _ ->
            // Программный буфер: аппаратный нельзя ни измерить, ни
            // гарантированно освободить вместе с кешем.
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE

            // Уменьшение при декодировании: целой в памяти картинка
            // не бывает никогда.
            val longest = maxOf(info.size.width, info.size.height)
            var sample = 1
            while (longest / sample > MAX_SIDE_PX) sample *= 2
            decoder.setTargetSampleSize(sample)

            // Оборванная картинка — не картинка: половина изображения
            // выглядела бы как то, что автор и хотел показать.
            decoder.setOnPartialImageListener { false }
        }

    companion object {
        /** Картинки крупнее этого сами не скачиваются. */
        const val AUTO_LOAD_BYTES = 8L * 1024 * 1024

        /** Наибольшая сторона картинки в ленте. */
        private const val MAX_SIDE_PX = 1280

        /** Память под расшифрованные картинки одного экрана. */
        private const val CACHE_BYTES = 48 * 1024 * 1024
    }
}

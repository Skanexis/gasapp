// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * 🔐 Запись файла, которая переживает отключение питания.
 *
 * # Что здесь чинится
 *
 * Соль (`gasapp.salt`) и аппаратная половина ключа (`gasapp.hw`) — это
 * часть ключа базы. Они писались `File.writeBytes`: без `fsync` и
 * поверх файла. После аварийной остановки эмулятора (2026-09-24)
 * на диске остались `gasapp.db` на 212 КБ и **пустые** `gasapp.salt`
 * и `gasapp.hw`: база успела лечь на диск, её ключ — нет.
 *
 * На телефоне то же самое делает разряд батареи или зависание сразу
 * после регистрации. Файловые системы Android (ext4, f2fs) откладывают
 * запись содержимого, и файл без `fsync` после сбоя питания бывает
 * нулевой длины. Такую базу не откроет уже ничто — ни верный PIN,
 * ни мы: половины ключа больше нет.
 *
 * # Как устроено
 *
 * Классическая схема: содержимое пишется во временный файл рядом,
 * сбрасывается на носитель (`FileDescriptor.sync`), и только потом
 * временный файл атомарно переименовывается в целевой. После сбоя
 * на диске либо прежний файл целиком, либо новый целиком.
 *
 * ⚠️ Каталог после переименования не синхронизируется: из Java на
 * Android открыть каталог для `fsync` нельзя. Переименование может
 * не пережить сбой питания в ту же долю секунды — тогда файла нет
 * вовсе, а не пустой, и приложение увидит «аккаунта нет», а не
 * испорченный аккаунт.
 */
object DurableFile {

    /**
     * Записывает [bytes] в [target] атомарно и с `fsync`.
     *
     * @throws IOException запись не удалась; прежнее содержимое
     *   [target], если оно было, не тронуто
     */
    fun write(target: File, bytes: ByteArray) {
        val temporary = File(target.parentFile, ".${target.name}.tmp")

        try {
            FileOutputStream(temporary).use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }

            Files.move(
                temporary.toPath(),
                target.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (failure: IOException) {
            temporary.delete()
            throw failure
        }
    }
}

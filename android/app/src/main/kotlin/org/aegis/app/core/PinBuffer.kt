// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

/**
 * 🔐 Набираемый PIN — в байтовом массиве, который затирается.
 *
 * # Почему не `String` и не `StringBuilder`
 *
 * `String` в Kotlin неизменяема — затереть её нельзя, она живёт в куче
 * до сборки мусора и после неё, пока память не переиспользована.
 * `StringBuilder.setLength(0)` меняет только длину: символы остаются
 * в его массиве. Дамп памяти запертого приложения на эмуляторе
 * (2026-09-25) показывал PIN в куче Java именно так.
 *
 * Здесь цифры лежат в `ByteArray` фиксированной длины и обнуляются
 * при удалении, при [clear] и при [take]; через FFI PIN уходит тем же
 * массивом, и ядро держит его в `Zeroizing`.
 */
class PinBuffer {

    private val digits = ByteArray(Pin.LENGTH)

    /** Сколько цифр набрано. */
    var length: Int = 0
        private set

    /** Набраны ли все цифры. */
    val isComplete: Boolean
        get() = length == Pin.LENGTH

    /** Добавляет цифру; лишние сверх длины PIN не принимаются. */
    fun append(digit: Char): Boolean {
        if (length >= Pin.LENGTH || digit !in '0'..'9') {
            return false
        }

        digits[length] = digit.code.toByte()
        length++

        return true
    }

    /** Убирает последнюю цифру и затирает её место. */
    fun removeLast() {
        if (length == 0) return

        length--
        digits[length] = 0
    }

    /**
     * Отдаёт копию набранного и затирает буфер.
     *
     * 🔐 Копию обнуляет вызывающий — сразу после использования
     * (`pin.fill(0)` в `finally`).
     */
    fun take(): ByteArray {
        val pin = digits.copyOf(length)
        clear()

        return pin
    }

    /** 🔐 Затирает набранное. */
    fun clear() {
        digits.fill(0)
        length = 0
    }
}

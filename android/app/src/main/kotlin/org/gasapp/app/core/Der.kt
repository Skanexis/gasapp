// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import java.math.BigInteger

/**
 * Минимальный разбор ASN.1 DER — ровно столько, сколько нужно
 * [KeyAttestation].
 *
 * # Почему свой, а не BouncyCastle
 *
 * Из всего ASN.1 здесь нужно одно расширение сертификата. BouncyCastle
 * добавил бы в APK несколько мегабайт кода, в котором разбирается всё
 * остальное, — то есть поверхность разбора недоверенного входа, которую
 * нам не нужно ни исполнять, ни проверять.
 *
 * # 🔐 Вход считается враждебным
 *
 * Сертификат аттестации приходит из Keystore, но на устройстве с root
 * его подменяют — ровно это аттестация и призвана заметить. Поэтому:
 *
 *  * длина каждого элемента сверяется с остатком буфера **до** чтения;
 *  * неопределённая длина (`0x80`) отвергается: в DER её нет;
 *  * длина кодируется не более чем четырьмя байтами и не превышает
 *    [Int.MAX_VALUE] — больше не бывает ни в одном сертификате;
 *  * номер тега не превышает 2^21: у аттестации максимум — 719.
 *
 * Любое нарушение — [MalformedDer], а не частичный результат.
 * Разбор, который «доверяет, сколько смог прочитать», превращает
 * обрезанную запись в правдоподобную.
 */
internal object Der {

    const val CLASS_UNIVERSAL = 0
    const val CLASS_CONTEXT = 2

    const val TAG_BOOLEAN = 1
    const val TAG_INTEGER = 2
    const val TAG_OCTET_STRING = 4
    const val TAG_ENUMERATED = 10
    const val TAG_SEQUENCE = 16
    const val TAG_SET = 17

    /** Нарушение кодировки. Текст — для журнала разработчика, не для экрана. */
    class MalformedDer(message: String) : IllegalArgumentException(message)

    /** Один элемент: тег и содержимое. */
    class Element(
        val tagClass: Int,
        val constructed: Boolean,
        val tagNumber: Int,
        val content: ByteArray,
    ) {
        fun isUniversal(tag: Int): Boolean = tagClass == CLASS_UNIVERSAL && tagNumber == tag

        fun isContext(tag: Int): Boolean = tagClass == CLASS_CONTEXT && tagNumber == tag

        /** Вложенные элементы; только для составных. */
        fun children(): List<Element> {
            if (!constructed) throw MalformedDer("не составной элемент")

            return parseAll(content)
        }

        fun expect(tag: Int): Element {
            if (!isUniversal(tag)) throw MalformedDer("ожидался тег $tag, получен $tagClass/$tagNumber")

            return this
        }

        fun asInteger(): BigInteger {
            if (!(isUniversal(TAG_INTEGER) || isUniversal(TAG_ENUMERATED)) || content.isEmpty()) {
                throw MalformedDer("не целое")
            }

            return BigInteger(content)
        }

        /** Малое целое: уровни защиты, состояния загрузки, версии. */
        fun asSmallInt(): Int {
            val value = asInteger()

            if (value.bitLength() > 31) throw MalformedDer("целое вне диапазона")

            return value.toInt()
        }

        fun asBoolean(): Boolean {
            if (!isUniversal(TAG_BOOLEAN) || content.size != 1) throw MalformedDer("не логическое")

            return content[0] != 0.toByte()
        }

        fun asOctets(): ByteArray {
            if (!isUniversal(TAG_OCTET_STRING)) throw MalformedDer("не строка октетов")

            return content
        }
    }

    /** Ровно один элемент, без хвоста. */
    fun parseSingle(bytes: ByteArray): Element {
        val all = parseAll(bytes)

        if (all.size != 1) throw MalformedDer("ожидался один элемент, получено ${all.size}")

        return all[0]
    }

    /** Последовательность элементов, занимающая буфер целиком. */
    fun parseAll(bytes: ByteArray): List<Element> {
        val out = mutableListOf<Element>()
        var pos = 0

        while (pos < bytes.size) {
            val (element, next) = parseAt(bytes, pos)
            out += element
            pos = next
        }

        return out
    }

    private fun parseAt(bytes: ByteArray, start: Int): Pair<Element, Int> {
        var pos = start

        fun next(): Int {
            if (pos >= bytes.size) throw MalformedDer("обрыв записи")

            return bytes[pos++].toInt() and 0xFF
        }

        val first = next()
        val tagClass = first ushr 6
        val constructed = first and 0x20 != 0
        var tagNumber = first and 0x1F

        if (tagNumber == 0x1F) {
            // Длинная форма номера тега: по семь бит, старший бит —
            // «дальше ещё». Ведущий ноль запрещён DER.
            tagNumber = 0
            var octets = 0

            do {
                val b = next()

                if (octets == 0 && b == 0x80) throw MalformedDer("ведущий ноль в номере тега")

                tagNumber = (tagNumber shl 7) or (b and 0x7F)
                octets += 1

                if (octets > MAX_TAG_OCTETS) throw MalformedDer("номер тега слишком велик")
            } while (b and 0x80 != 0)
        }

        val lengthByte = next()

        val length = when {
            lengthByte < 0x80 -> lengthByte
            lengthByte == 0x80 -> throw MalformedDer("неопределённая длина")
            else -> {
                val count = lengthByte and 0x7F

                if (count > MAX_LENGTH_OCTETS) throw MalformedDer("длина слишком велика")

                var value = 0L
                repeat(count) { value = (value shl 8) or next().toLong() }

                if (value > Int.MAX_VALUE) throw MalformedDer("длина слишком велика")

                value.toInt()
            }
        }

        if (length > bytes.size - pos) throw MalformedDer("длина больше остатка записи")

        val content = bytes.copyOfRange(pos, pos + length)

        return Element(tagClass, constructed, tagNumber, content) to (pos + length)
    }

    /** Три октета по семь бит — до 2^21; у аттестации теги до 719. */
    private const val MAX_TAG_OCTETS = 3

    private const val MAX_LENGTH_OCTETS = 4
}

// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import java.security.MessageDigest

/**
 * 🔐 Отпечаток ключа, которым сейчас открыта база.
 *
 * Нужен, чтобы проверить PIN, не открывая базу второй раз: второй
 * экземпляр мессенджера над той же базой разошёлся бы с первым
 * в состояниях Double Ratchet. Проверка — сравнение SHA-256 ключа,
 * выведенного из введённого PIN, с отпечатком ключа открытой базы.
 *
 * Хранится только отпечаток и только пока база открыта: сам ключ
 * держит SQLCipher в нативной памяти, и отпечаток рядом с ним ничего
 * к этому не добавляет, а после закрытия стирается.
 */
internal class OpenedKey {
    private var digest: ByteArray? = null

    /** Запоминает отпечаток ключа открытой базы. */
    fun remember(key: ByteArray) {
        forget()
        digest = sha256(key)
    }

    /** Забывает отпечаток: база закрыта. */
    fun forget() {
        digest?.fill(0)
        digest = null
    }

    /**
     * Тот ли это ключ, которым открыта база.
     *
     * `false`, если база закрыта: подтвердить нечего.
     */
    fun matches(key: ByteArray): Boolean {
        val expected = digest ?: return false

        // Сравнение за постоянное время: отпечаток не секрет, но
        // привычка сравнивать ключи иначе — повод для ошибки в месте,
        // где она уже не безобидна.
        return MessageDigest.isEqual(sha256(key), expected)
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)
}

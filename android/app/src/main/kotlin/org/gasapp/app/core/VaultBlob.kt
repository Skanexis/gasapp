// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import java.io.File

/**
 * 🔐 Стирание шифроблоба удалённого файла хранилища.
 *
 * # Почему путь проверяется
 *
 * Ядро убирает запись о файле и возвращает путь к его блобу: файловой
 * системы ядро не касается, стирает платформа. Путь при этом приходит
 * **из базы**, а не из кода этого экрана.
 *
 * Поэтому стирается только то, что лежит внутри каталога хранилища.
 * Запись, указывающая наружу — `../../databases/gasapp.db`, чужой
 * абсолютный путь, — не должна превращать «удалить файл из хранилища»
 * в «удалить что угодно, до чего дотягивается приложение». Базу
 * для этого пришлось бы подделать, а она зашифрована; но проверка
 * стоит одной строки, а цена её отсутствия — чужой файл.
 *
 * # Чего это не даёт
 *
 * Невосстановимости с флеш-памяти: удаление файла не затирает ячейки.
 * Блоб при этом зашифрован ключом хранилища, так что оставшиеся ячейки
 * без ключа — шум.
 */
object VaultBlob {

    /**
     * Стирает блоб, если он лежит внутри [directory].
     *
     * Возвращает `true`, если файл был и удалён. Путь снаружи каталога
     * не трогается и даёт `false`.
     */
    fun deleteInside(directory: File, location: String): Boolean {
        val root = runCatching { directory.canonicalFile }.getOrNull() ?: return false
        val target = runCatching { File(location).canonicalFile }.getOrNull() ?: return false

        // Сравнение по компонентам пути, а не по префиксу строки:
        // `/vault-old/x` начинается с `/vault`, но внутри него не лежит.
        if (target.parentFile?.let { isInside(it, root) } != true) {
            return false
        }

        return target.isFile && target.delete()
    }

    private fun isInside(candidate: File, root: File): Boolean {
        var current: File? = candidate

        while (current != null) {
            if (current == root) {
                return true
            }
            current = current.parentFile
        }

        return false
    }
}

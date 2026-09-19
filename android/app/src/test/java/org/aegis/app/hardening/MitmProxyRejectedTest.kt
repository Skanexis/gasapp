// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import org.w3c.dom.Node

/**
 * 🧪 `mitm_proxy_rejected` — проверка раздела 25 (MASVS NETWORK-2)
 * и пункта M8 «Тест: MITM-прокси отвергается».
 *
 * # Что именно проверяется
 *
 * Не поведение сети, а **политика релизной сборки**. Перехват трафика
 * на Android без root делается ровно одним способом: сертификат прокси
 * (Burp, mitmproxy, корпоративный MDM) ставится в пользовательское
 * хранилище, и приложение, доверяющее `src="user"`, начинает показывать
 * свой трафик как на ладони.
 *
 * Значит, отвергает MITM не код, а отсутствие `<certificates src="user" />`
 * в `network-security-config`. Проверять это сетевым тестом — значит
 * поднимать прокси в CI ради того, что видно в одной строке XML.
 *
 * # Почему файл читается с диска
 *
 * Проверяется конфигурация **релиза**, а юнит-тесты идут на отладочном
 * варианте: через `R.xml` сюда попала бы отладочная версия — та самая,
 * которая локальному CA как раз доверяет, и тест был бы красным
 * по ложной причине.
 *
 * Чтение файла заодно совпадает с тем, что делает аудитор: смотрит
 * в исходник политики, а не в собранный ресурс.
 *
 * # Что этот тест не проверяет
 *
 * Что сервер действительно отвечает ключом с этим пином. Это проверяется
 * против живого сервера — `server/deploy/compute-pin.sh --host` — и входит
 * в чек-лист перед релизом (docs/ops/cert-pin-rotation.md).
 */
class MitmProxyRejectedTest {

    /**
     * 🔐 Релизная политика не доверяет пользовательским корням.
     *
     * Главная проверка файла. Именно её нарушение открывает перехват
     * всем, кто может поставить сертификат в профиль устройства.
     */
    @Test
    fun release_config_does_not_trust_user_certificates() {
        val sources = releaseConfig().elements("certificates")
            .map { it.getAttribute("src") }

        assertTrue("в релизной политике нет ни одного trust-anchor", sources.isNotEmpty())

        assertEquals(
            "релиз доверяет пользовательским корням — MITM через профиль устройства",
            emptyList<String>(),
            sources.filter { it != "system" },
        )
    }

    /**
     * 🔐 Отладочный локальный CA не доехал до релиза.
     *
     * Отдельная проверка, потому что дыра была настоящей: политика
     * лежала в `src/main/`, комментарий в ней утверждал, что релизная
     * версия отдельная, а её не существовало. Релизный APK доверял
     * `@raw/aegis_local_ca` для 10.0.2.2 и 192.168.1.15.
     */
    @Test
    fun release_config_has_no_local_ca() {
        // По значениям атрибутов, а не по тексту файла.
        //
        // Первая версия искала «aegis_local_ca» во всём файле и падала
        // на комментарии, который объясняет, почему этого корня здесь
        // больше нет. Проверка обязана отличать ссылку на ресурс
        // от рассказа о ней.
        val bundled = releaseConfig().elements("certificates")
            .map { it.getAttribute("src") }
            .filter { it.startsWith("@") }

        assertEquals(
            "в релизной политике остался встроенный сертификат",
            emptyList<String>(),
            bundled,
        )
        assertTrue(
            "сертификат локального CA лежит вне src/debug",
            !File(moduleDir(), "src/main/res/raw/aegis_local_ca.crt").exists() &&
                !File(moduleDir(), "src/release/res/raw/aegis_local_ca.crt").exists(),
        )
    }

    /** Открытый HTTP запрещён везде: и в базовой политике, и по доменам. */
    @Test
    fun release_config_forbids_cleartext_everywhere() {
        val offenders = releaseConfig()
            .elements("base-config", "domain-config")
            .filter { it.getAttribute("cleartextTrafficPermitted") != "false" }
            .map { it.tagName }

        assertEquals("разрешён открытый HTTP", emptyList<String>(), offenders)
    }

    /**
     * Правило двух пинов (раздел 14.3): их не меньше двух и они разные.
     *
     * 🔐 Различие проверяется отдельно от количества. Два одинаковых
     * пина удовлетворяют счёту и не дают ничего: в момент, когда ключ
     * придётся сменить, заменять его будет нечем, а клиент уже не сможет
     * получить ни нового пина, ни сообщения об ошибке.
     */
    @Test
    fun release_config_pins_two_distinct_keys() {
        val sets = releaseConfig().elements("pin-set")

        assertTrue("в релизной политике нет ни одного pin-set", sets.isNotEmpty())

        sets.forEach { set ->
            val pins = set.elements("pin").map { it.textContent.trim() }

            assertTrue("в наборе меньше двух пинов: $pins", pins.size >= 2)
            assertEquals("пины в наборе повторяются: $pins", pins.size, pins.toSet().size)
        }
    }

    /**
     * У набора пинов есть срок годности.
     *
     * 🔐 Предохранитель, а не послабление: набор без срока, про который
     * забыли, однажды обрывает связь навсегда — и починить это можно
     * только обновлением через магазин. Срок превращает забытую ротацию
     * в потерю пиннинга, а не в потерю приложения.
     */
    @Test
    fun every_pin_set_expires() {
        releaseConfig().elements("pin-set").forEach { set ->
            assertTrue(
                "у набора пинов нет expiration",
                set.getAttribute("expiration").isNotBlank(),
            )
        }
    }

    private fun releaseFile(): File =
        File(moduleDir(), "src/release/res/xml/network_security_config.xml").also {
            assertTrue("нет релизной сетевой политики: ${it.path}", it.isFile)
        }

    private fun releaseConfig(): Element =
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(releaseFile())
            .documentElement

    /**
     * Каталог модуля `app`.
     *
     * Рабочий каталог юнит-теста Gradle — каталог модуля, но полагаться
     * на это молча нельзя: при запуске из IDE он бывает корнем проекта.
     * Поэтому путь проверяется и при необходимости достраивается.
     */
    private fun moduleDir(): File {
        val here = File("").absoluteFile

        return if (File(here, "src/release").exists()) here else File(here, "android/app")
    }

    private fun Element.elements(vararg tags: String): List<Element> {
        val found = mutableListOf<Element>()

        fun walk(node: Node) {
            if (node is Element && node.tagName in tags) {
                found += node
            }

            val children = node.childNodes

            for (index in 0 until children.length) {
                walk(children.item(index))
            }
        }

        walk(this)

        return found
    }
}

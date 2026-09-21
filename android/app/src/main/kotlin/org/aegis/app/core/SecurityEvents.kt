// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import org.aegis.app.R

/**
 * 🔐 Подписи событий журнала безопасности.
 *
 * # Что здесь чинится
 *
 * Журнал безопасности писался — смена ключа собеседника, сверка и её
 * отзыв, смена ключа сервера sealed sender, восстановление из копии, —
 * но **прочитать его было негде**. `security_events` был выведен через
 * FFI и не вызывался ни одним экраном, а комментарии в ядре объясняли
 * запись тем, что «человек должен иметь возможность увидеть, когда
 * она случилась».
 *
 * # Почему неизвестное событие показывается, а не прячется
 *
 * Тип, которого нет в [labels], — событие из версии ядра новее этого
 * экрана. Спрятать его значило бы скрыть событие безопасности только
 * потому, что для него не нашлось красивой подписи. Показывается
 * сырой тип: некрасиво, но честно.
 *
 * ⚠️ Состав [labels] сверяется со списком событий, которые пишет ядро
 * (`tools/check-security-events-labelled.py`): событие без подписи
 * не должно появиться незаметно.
 */
object SecurityEvents {

    /** Подпись для каждого типа события, который пишет ядро. */
    val labels: Map<String, Int> = mapOf(
        "contact_identity_changed" to R.string.security_event_contact_identity_changed,
        "contact_verified" to R.string.security_event_contact_verified,
        "contact_verification_revoked" to R.string.security_event_contact_verification_revoked,
        "sealed_sender_server_key_changed" to R.string.security_event_server_key_changed,
        "sealed_sender_access_rejected" to R.string.security_event_access_rejected,
        "sealed_sender_certificate_mismatch" to R.string.security_event_certificate_mismatch,
        "backup_restored" to R.string.security_event_backup_restored,
    )

    /** Подпись события либо `null`, если тип неизвестен этому экрану. */
    fun labelFor(type: String): Int? = labels[type]
}

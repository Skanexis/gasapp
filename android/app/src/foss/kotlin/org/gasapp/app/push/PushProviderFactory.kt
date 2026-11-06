// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.push

import android.content.Context
import uniffi.gasapp.Messenger

/** Сборка без Google: пушей нет, уведомления — опросом по токену (ADR-040). */
object PushProviderFactory {
    fun create(): PushProvider = NoPushProvider
}

internal object NoPushProvider : PushProvider {
    override val displayName: String = "Проверка по расписанию"

    override fun isAvailable(context: Context): Boolean = false

    override fun register(context: Context, messenger: Messenger) = Unit

    override fun unregister(context: Context, messenger: Messenger) = Unit
}

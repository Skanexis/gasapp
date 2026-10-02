// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/**
 * Область корутин на весь процесс — для работы, которую нельзя отменять
 * вместе с экраном.
 *
 * 🔐 Проверка PIN — такая работа: `lifecycleScope` экрана отменяется
 * поворотом телефона, и всё, что шло после проверки (запись исхода,
 * стирание после десятой неверной), не выполнялось (аудит 2026-10-02,
 * A-1). Результат на экран доставляется, только если экран ещё жив.
 */
object AppScope : CoroutineScope by CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

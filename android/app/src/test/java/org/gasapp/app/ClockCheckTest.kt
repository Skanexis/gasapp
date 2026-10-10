// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import org.gasapp.app.net.ClockCheck
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Полоса «проверьте время» — только при расхождении, с которым сервер откажет. */
class ClockCheckTest {

    private val now = 1_800_000_000_000L
    private val minute = 60_000L

    @Test
    fun small_skew_is_fine() {
        ClockCheck.observe(now - 2 * minute, now)
        assertFalse(ClockCheck.off)

        ClockCheck.observe(now + 2 * minute, now)
        assertFalse(ClockCheck.off)
    }

    @Test
    fun large_skew_either_way_is_reported() {
        ClockCheck.observe(now - 10 * minute, now)
        assertTrue("часы спешат", ClockCheck.off)

        ClockCheck.observe(now + 10 * minute, now)
        assertTrue("часы отстают", ClockCheck.off)
    }

    @Test
    fun a_response_without_a_date_changes_nothing() {
        ClockCheck.observe(now, now)
        ClockCheck.observe(0, now)
        assertFalse(ClockCheck.off)
    }
}

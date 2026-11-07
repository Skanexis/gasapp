package org.gasapp.app.components

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.paparoni.paparazzi.Paparazzi
import com.paparoni.paparazzi.PaparazziRule
import org.junit.Rule
import org.junit.Test

/**
 * Snapshot tests for GasAppListRow component using Paparazzi.
 * These tests verify the visual appearance of the list row in different states.
 */
class GasAppListRowSnapshotTest {

    @get:Rule
    val paparazzi = PaparazziRule(ApplicationProvider.getApplicationContext())

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `list row normal state snapshot`() {
        val listRow = GasAppListRow(context).apply {
            setPadding(16, 16, 16, 16)
            setStateBackgrounds(
                android.R.drawable.menuitem_background, // normal
                android.R.drawable.menuitem_background_selected, // selected
                android.R.drawable.menuitem_background_activated, // activated
                android.R.drawable.menuitem_background_disabled // disabled
            )
            configure("Normal Row", "This is a subtitle", "���������📝")
        }
        paparazzi.snapshot(listRow)
    }

    @Test
    fun `list row selected state snapshot`() {
        val listRow = GasAppListRow(context).apply {
            setPadding(16, 16, 16, 16)
            setStateBackgrounds(
                android.R.drawable.menuitem_background, // normal
                android.R.drawable.menuitem_background_selected, // selected
                android.R.drawable.menuitem_background_activated, // activated
                android.R.drawable.menuitem_background_disabled // disabled
            )
            configure("Selected Row", "This row is selected", "��������⭐")
            setSelected(true)
        }
        paparazzi.snapshot(listRow)
    }

    @Test
    fun `list row activated state snapshot`() {
        val listRow = GasAppListRow(context).apply {
            setPadding(16, 16, 16, 16)
            setStateBackgrounds(
                android.R.drawable.menuitem_background, // normal
                android.R.drawable.menuitem_background_selected, // selected
                android.R.drawable.menuitem_background_activated, // activated
                android.R.drawable.menuitem_background_disabled // disabled
            )
            configure("Activated Row", "This row is activated", "��������✅")
            setActivated(true)
        }
        paparazzi.snapshot(listRow)
    }

    @Test
    fun `list row disabled state snapshot`() {
        val listRow = GasAppListRow(context).apply {
            setPadding(16, 16, 16, 16)
            setStateBackgrounds(
                android.R.drawable.menuitem_background, // normal
                android.R.drawable.menuitem_background_selected, // selected
                android.R.drawable.menuitem_background_activated, // activated
                android.R.drawable.menuitem_background_disabled // disabled
            )
            configure("Disabled Row", "This row is disabled", "���������🚫")
            setEnabled(false)
        }
        paparazzi.snapshot(listRow)
    }
}

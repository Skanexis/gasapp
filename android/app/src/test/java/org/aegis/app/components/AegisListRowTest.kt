package org.aegis.app.components

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Unit tests for AegisListRow component.
 */
@RunWith(AndroidJUnit4::class)
class AegisListRowTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `list row initializes in normal state`() {
        val listRow = AegisListRow(context)
        assertFalse(listRow.isSelected)
        assertFalse(listRow.isActivated)
        assertTrue(listRow.isEnabled)
    }

    @Test
    fun `list row can be selected`() {
        val listRow = AegisListRow(context)
        listRow.setSelected(true)

        assertTrue(listRow.isSelected())
        assertFalse(listRow.isActivated)
    }

    @Test
    fun `list row can be activated`() {
        val listRow = AegisListRow(context)
        listRow.setActivated(true)

        assertFalse(listRow.isSelected())
        assertTrue(listRow.isActivated())
    }

    @Test
    fun `list row configure sets data correctly`() {
        val listRow = AegisListRow(context)
        listRow.configure("Test Title", "Test Subtitle", "���📝")

        assertEquals(listRow.getTitle(), "Test Title")
        assertEquals(listRow.getSubtitle(), "Test Subtitle")
        // Icon testing would be more complex in a unit test
    }

    @Test
    fun `list row state backgrounds can be set`() {
        val listRow = AegisListRow(context)
        // Just verify it doesn't crash
        listRow.setStateBackgrounds(
            android.R.drawable.menuitem_background, // normal
            android.R.drawable.menuitem_background_selected, // selected
            android.R.drawable.menuitem_background_activated, // activated
            android.R.drawable.menuitem_background_disabled // disabled
        )
        assertTrue(true) // If we got here without exception, the test passes
    }
}
package org.aegis.app.components

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Unit tests for AegisTextField component.
 */
@RunWith(AndroidJUnit4::class)
class AegisTextFieldTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `text field initializes in normal state`() {
        val textField = AegisTextField(context)
        assertFalse(textField.isInErrorState())
        assertTrue(textField.isEnabled)
    }

    @Test
    fun `text field shows error state correctly`() {
        val textField = AegisTextField(context)
        textField.showError("Test error")

        assertTrue(textField.isInErrorState())
        assertEquals(textField.getError(), "Test error")
    }

    @Test
    fun `text field clears error state correctly`() {
        val textField = AegisTextField(context)
        textField.showError("Test error")
        textField.clearError()

        assertFalse(textField.isInErrorState())
        assertNull(textField.getError())
    }

    @Test
    fun `text field state backgrounds can be set`() {
        val textField = AegisTextField(context)
        // Just verify it doesn't crash
        textField.setStateBackgrounds(
            android.R.drawable.edit_text, // normal
            android.R.drawable.edit_text_focused, // focused
            android.R.drawable.edit_text_disabled, // disabled
            android.R.drawable.edit_text // error
        )
        assertTrue(true) // If we got here without exception, the test passes
    }
}
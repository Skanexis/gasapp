package org.aegis.app.components

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Unit tests for AegisButton component.
 * These tests verify the basic functionality of the button states.
 */
@RunWith(AndroidJUnit4::class)
class AegisButtonTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `button initializes in normal state`() {
        val button = AegisButton(context)
        assertFalse(button.isLoading)
        assertFalse(button.isError)
        assertTrue(button.isEnabled)
    }

    @Test
    fun `button shows loading state correctly`() {
        val button = AegisButton(context)
        button.showLoading()

        assertTrue(button.isLoading)
        assertFalse(button.isError)
        assertFalse(button.isEnabled) // Should be disabled during loading
        assertEquals(button.text, button.context.getString(org.aegis.app.R.string.button_loading))
    }

    @Test
    fun `button hides loading state correctly`() {
        val button = AegisButton(context)
        button.showLoading()
        button.hideLoading()

        assertFalse(button.isLoading)
        assertFalse(button.isError)
        assertTrue(button.isEnabled)
    }

    @Test
    fun `button shows error state correctly`() {
        val button = AegisButton(context)
        button.showError("Test error")

        assertFalse(button.isLoading)
        assertTrue(button.isError)
        assertTrue(button.isEnabled) // Should be enabled but in error state
        assertEquals(button.text, "Test error")
    }

    @Test
    fun `button hides error state correctly`() {
        val button = AegisButton(context)
        button.showError("Test error")
        button.hideError()

        assertFalse(button.isLoading)
        assertFalse(button.isError)
        assertTrue(button.isEnabled)
    }

    @Test
    fun `button state backgrounds can be set`() {
        val button = AegisButton(context)
        // Just verify it doesn't crash - actual background testing would require more setup
        button.setStateBackgrounds(
            android.R.drawable.btn_default, // normal
            android.R.drawable.btn_default_pressed, // pressed
            android.R.drawable.btn_default_focused, // focused
            android.R.drawable.btn_default_disabled, // disabled
            android.R.drawable.btn_default, // loading
            android.R.drawable.btn_default // error
        )
        assertTrue(true) // If we got here without exception, the test passes
    }
}
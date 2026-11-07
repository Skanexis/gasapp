package org.gasapp.app.components

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.paparoni.paparazzi.Paparazzi
import com.paparoni.paparazzi.PaparazziRule
import org.junit.Rule
import org.junit.Test

/**
 * Snapshot tests for GasAppTextField component using Paparazzi.
 * These tests verify the visual appearance of the text field in different states.
 */
class GasAppTextFieldSnapshotTest {

    @get:Rule
    val paparazzi = PaparazziRule(ApplicationProvider.getApplicationContext())

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `text field normal state snapshot`() {
        val textField = GasAppTextField(context).apply {
            setHint("Enter text")
            setStateBackgrounds(
                android.R.drawable.edit_text, // normal
                android.R.drawable.edit_text_focused, // focused
                android.R.drawable.edit_text_disabled, // disabled
                android.R.drawable.edit_text // error
            )
        }
        paparazzi.snapshot(textField)
    }

    @Test
    fun `text field focused state snapshot`() {
        val textField = GasAppTextField(context).apply {
            setHint("Focused Field")
            setStateBackgrounds(
                android.R.drawable.edit_text, // normal
                android.R.drawable.edit_text_focused, // focused
                android.R.drawable.edit_text_disabled, // disabled
                android.R.drawable.edit_text // error
            )
            // Simulate focus by requesting focus
            requestFocus()
        }
        paparazzi.snapshot(textField)
    }

    @Test
    fun `text field error state snapshot`() {
        val textField = GasAppTextField(context).apply {
            setHint("Error Field")
            setStateBackgrounds(
                android.R.drawable.edit_text, // normal
                android.R.drawable.edit_text_focused, // focused
                android.R.drawable.edit_text_disabled, // disabled
                android.R.drawable.edit_text // error
            )
            showError("Invalid input")
        }
        paparazzi.snapshot(textField)
    }

    @Test
    fun `text field disabled state snapshot`() {
        val textField = GasAppTextField(context).apply {
            setHint("Disabled Field")
            setStateBackgrounds(
                android.R.drawable.edit_text, // normal
                android.R.drawable.edit_text_focused, // focused
                android.R.drawable.edit_text_disabled, // disabled
                android.R.drawable.edit_text // error
            )
            isEnabled = false
        }
        paparazzi.snapshot(textField)
    }
}

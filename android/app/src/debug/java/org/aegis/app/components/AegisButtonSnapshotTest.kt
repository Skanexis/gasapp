package org.aegis.app.components

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.paparoni.paparazzi.Paparazzi
import com.paparoni.paparazzi.PaparazziRule
import org.junit.Rule
import org.junit.Test

/**
 * Snapshot tests for AegisButton component using Paparazzi.
 * These tests verify the visual appearance of the button in different states.
 */
class AegisButtonSnapshotTest {

    @get:Rule
    val paparazzi = PaparazziRule(ApplicationProvider.getApplicationContext())

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `button normal state snapshot`() {
        val button = AegisButton(context).apply {
            setText("Normal Button")
            setStateBackgrounds(
                android.R.drawable.btn_default, // normal
                android.R.drawable.btn_default_pressed, // pressed
                android.R.drawable.btn_default_focused, // focused
                android.R.drawable.btn_default_disabled, // disabled
                android.R.drawable.btn_default, // loading
                android.R.drawable.btn_default // error
            )
        }
        paparazzi.snapshot(button)
    }

    @Test
    fun `button loading state snapshot`() {
        val button = AegisButton(context).apply {
            setText("Loading Button")
            setStateBackgrounds(
                android.R.drawable.btn_default, // normal
                android.R.drawable.btn_default_pressed, // pressed
                android.R.drawable.btn_default_focused, // focused
                android.R.drawable.btn_default_disabled, // disabled
                android.R.drawable.btn_default, // loading
                android.R.drawable.btn_default // error
            )
            showLoading()
        }
        paparazzi.snapshot(button)
    }

    @Test
    fun `button error state snapshot`() {
        val button = AegisButton(context).apply {
            setText("Error Button")
            setStateBackgrounds(
                android.R.drawable.btn_default, // normal
                android.R.drawable.btn_default_pressed, // pressed
                android.R.drawable.btn_default_focused, // focused
                android.R.drawable.btn_default_disabled, // disabled
                android.R.drawable.btn_default, // loading
                android.R.drawable.btn_default // error
            )
            showError("Error occurred")
        }
        paparazzi.snapshot(button)
    }

    @Test
    fun `button disabled state snapshot`() {
        val button = AegisButton(context).apply {
            setText("Disabled Button")
            setStateBackgrounds(
                android.R.drawable.btn_default, // normal
                android.R.drawable.btn_default_pressed, // pressed
                android.R.drawable.btn_default_focused, // focused
                android.R.drawable.btn_default_disabled, // disabled
                android.R.drawable.btn_default, // loading
                android.R.drawable.btn_default // error
            )
            isEnabled = false
        }
        paparazzi.snapshot(button)
    }
}
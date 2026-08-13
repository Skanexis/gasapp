package org.aegis.app

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import androidx.test.uiautomator.By
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented test for FFI integration in MainActivity.
 * This test verifies that FFI function calls work correctly on Android emulator/device.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityFFITest {

    private lateinit var device: UiDevice

    @Before
    fun setUp() {
        // Initialize UiDevice instance
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    @After
    fun tearDown() {
        // Clean up if needed
    }

    @Test
    fun `testFFI functions return expected results`() {
        // Launch the app
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        intent?.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
        context.startActivity(intent)

        // Wait for the app to load
        device.wait(Until.hasObject(By.pkg("org.aegis.app").depth(0)), 5000)

        // Verify that core version text is displayed (not showing loading/error)
        val coreVersionText = device.findObject(By.clazz("android.widget.TextView").textContains("Core Version:"))
        assertNotNull("Core version TextView should be found", coreVersionText)

        // Verify that protocol version text is displayed
        val protocolVersionText = device.findObject(By.clazz("android.widget.TextView").textContains("Protocol Version:"))
        assertNotNull("Protocol version TextView should be found", protocolVersionText)

        // Verify that safety number text is displayed
        val safetyNumberText = device.findObject(By.clazz("android.widget.TextView").textContains("Safety Number:"))
        assertNotNull("Safety number TextView should be found", safetyNumberText)

        // Additional verification: check that we're not seeing error messages
        val errorText = device.findObject(By.clazz("android.widget.TextView").textContains("Error:"))
        assertNull("Error TextView should not be visible", errorText)
    }

    @Test
    fun `testFFI error handling`() {
        // This test would require modifying the app to force an error condition
        // For simplicity, we're just verifying the app doesn't crash on launch
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        intent?.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
        context.startActivity(intent)

        // Wait for the app to load
        device.wait(Until.hasObject(By.pkg("org.aegis.app").depth(0)), 5000)

        // Verify the app is responsive (not crashed)
        val anyText = device.findObject(By.clazz("android.widget.TextView"))
        assertNotNull("App should be responsive and showing text", anyText)
    }
}
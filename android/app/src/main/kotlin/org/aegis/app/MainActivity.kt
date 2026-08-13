package org.aegis.app

import android.os.Bundle
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.aegis.FfiException

class MainActivity : AppCompatActivity() {

    private lateinit var coreVersionTextView: TextView
    private lateinit var protocolVersionTextView: TextView
    private lateinit var safetyNumberTextView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize views
        coreVersionTextView = findViewById(R.id.core_version_text)
        protocolVersionTextView = findViewById(R.id.protocol_version_text)
        safetyNumberTextView = findViewById(R.id.safety_number_text)

        // Initialize AEGIS components and fetch data
        initializeAegis()
    }

    private fun initializeAegis() {
        // Run FFI calls on a background thread to avoid blocking UI
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Get core version
                val coreVersion = uniffi.aegis.Aegis.coreVersion()

                // Get protocol version
                val protocolVersion = uniffi.aegis.Aegis.protocolVersion()

                // Format a sample safety number (using dummy data for demo)
                val localFingerprint = ByteArray(30) { 0x11.toByte() } // 30 bytes of 0x11
                val remoteFingerprint = ByteArray(30) { 0x22.toByte() } // 30 bytes of 0x22
                val safetyNumber = uniffi.aegis.Aegis.formatSafetyNumber(localFingerprint, remoteFingerprint)

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    coreVersionTextView.text = "Core Version: $coreVersion"
                    protocolVersionTextView.text = "Protocol Version: $protocolVersion"
                    safetyNumberTextView.text = "Safety Number:\n$safetyNumber"
                }
            } catch (e: FfiException) {
                // Handle FFI errors
                withContext(Dispatchers.Main) {
                    coreVersionTextView.text = "Error: ${e.message}"
                }
            } catch (e: Exception) {
                // Handle unexpected errors
                withContext(Dispatchers.Main) {
                    coreVersionTextView.text = "Unexpected Error: ${e.message}"
                }
            }
        }
    }
}
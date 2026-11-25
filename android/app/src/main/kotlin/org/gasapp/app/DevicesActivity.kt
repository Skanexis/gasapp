// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.res.ColorStateList
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.res.ResourcesCompat
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppGroup
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.SettingsRow
import uniffi.gasapp.FfiException
import uniffi.gasapp.FfiOwnDevice

/**
 * Устройства аккаунта — до пяти телефонов (`docs/protocol/MULTI-DEVICE.md`).
 *
 * Основной телефон сканирует QR нового, оба показывают шесть цифр, и
 * только после «Совпадают — подключить» новый получает доступ.
 *
 * 🔐 Цифры — защита от подмены QR: не совпали — подключать нельзя.
 * Названий моделей в списке нет: их пришлось бы отдавать серверу, а
 * другие устройства узнают о них только от него.
 */
class DevicesActivity : AppCompatActivity() {

    private lateinit var list: GasAppGroup
    private lateinit var linkButton: GasAppButton
    private lateinit var status: TextView

    private var devices: List<FfiOwnDevice> = emptyList()
    private var primary = false

    private val scan = registerForActivityResult(ScanActivity.Contract()) { payload ->
        if (payload != null) prepare(payload)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_devices)

        findViewById<ImageView>(R.id.devices_back).setOnClickListener { finish() }

        list = findViewById(R.id.devices_list)
        status = findViewById(R.id.devices_status)
        linkButton = findViewById(R.id.devices_link)
        linkButton.setOnClickListener {
            hideStatus()
            scan.launch(ScanActivity.Request(R.string.devices_link, R.string.scan_hint_device))
        }

        load()
    }

    private fun load() {
        lifecycleScope.launch {
            findViewById<View>(R.id.devices_loading).isVisible = devices.isEmpty()

            val result = io {
                Core.messenger().isPrimaryDevice() to
                    Core.messenger().ownDevices(System.currentTimeMillis())
            }

            findViewById<View>(R.id.devices_loading).isVisible = false

            result
                .onSuccess { (isPrimary, found) ->
                    primary = isPrimary
                    // Своё — первым, основное — следом.
                    devices = found.sortedWith(
                        compareByDescending<FfiOwnDevice> { it.thisDevice }.thenByDescending { it.primary },
                    )
                    render()
                }
                .onFailure { if (devices.isEmpty()) showStatus(getString(R.string.devices_load_failed), ok = false) }
        }
    }

    private fun render() {
        list.removeAllViews()

        for (device in devices) {
            val row = LayoutInflater.from(this).inflate(R.layout.item_settings_row, list, false)
            val canUnlink = primary && !device.thisDevice

            SettingsRow.bind(
                root = row,
                title = if (device.thisDevice) getString(R.string.devices_this_phone) else getString(R.string.devices_phone, shortId(device)),
                value = if (canUnlink) getString(R.string.devices_unlink) else null,
                icon = R.drawable.ic_mobile,
                destructive = false,
                onClick = if (canUnlink) ({ confirmUnlink(device) }) else null,
            )
            row.findViewById<TextView>(R.id.row_detail).apply {
                text = getString(if (device.primary) R.string.devices_primary else R.string.devices_linked)
                setTextColor(getColor(if (device.primary) R.color.accent_base else R.color.text_tertiary))
                visibility = View.VISIBLE
            }
            row.findViewById<TextView>(R.id.row_value).setTextColor(getColor(R.color.status_error))
            row.findViewById<View>(R.id.row_chevron).visibility = View.GONE
            row.findViewById<ImageView>(R.id.row_icon).imageTintList = ColorStateList.valueOf(
                getColor(if (device.thisDevice) R.color.accent_base else R.color.text_secondary),
            )

            list.addView(row)
        }

        val full = devices.size >= LIMIT
        linkButton.isVisible = primary
        linkButton.isEnabled = !full
        findViewById<TextView>(R.id.devices_link_hint).apply {
            isVisible = true
            setText(
                when {
                    !primary -> R.string.devices_not_primary
                    full -> R.string.devices_link_full
                    else -> R.string.devices_link_hint
                },
            )
        }
    }

    /** QR нового телефона → шесть цифр для сверки. */
    private fun prepare(uri: String) {
        linkButton.isLoading = true

        lifecycleScope.launch {
            val result = io { Core.messenger().prepareDeviceLink(uri.trim(), System.currentTimeMillis()) }

            linkButton.isLoading = false

            result
                .onSuccess(::confirmDigits)
                .onFailure { showStatus(errorText(it), ok = false) }
        }
    }

    private fun confirmDigits(code: String) {
        val digits = code.filter(Char::isDigit)
        val view = TextView(this).apply {
            text = if (digits.length == CODE_DIGITS) "${digits.take(3)} ${digits.takeLast(3)}" else digits
            typeface = ResourcesCompat.getFont(this@DevicesActivity, R.font.rubik)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, DIGITS_SP)
            letterSpacing = DIGITS_SPACING
            setTextColor(getColor(R.color.accent_base))
            gravity = Gravity.CENTER
            setPadding(0, dp(12), 0, dp(12))
            contentDescription = digits.toList().joinToString(" ")
        }

        GasAppDialog(this)
            .title(R.string.devices_compare_title)
            .message(R.string.devices_compare_message)
            .content(view)
            .alwaysSecure()
            .cancelable(false)
            .secondary()
            .primary(R.string.devices_compare_match, closeOnClick = false) { dialog -> approve(dialog, view.text) }
            .show()
    }

    private fun approve(dialog: GasAppDialog.Shown, code: CharSequence) {
        dialog.setBusy(true)

        lifecycleScope.launch {
            val result = io { Core.messenger().approveDeviceLink(System.currentTimeMillis()) }

            dialog.setBusy(false)
            dialog.dismiss()

            result
                .onSuccess {
                    // Цифры остаются на экране: сверяют их с новым телефоном,
                    // который покажет их только теперь.
                    findViewById<TextView>(R.id.devices_code).text = code
                    findViewById<View>(R.id.devices_code_panel).isVisible = true
                    waitForNewDevice()
                    findViewById<View>(R.id.devices_code_panel).isVisible = false
                }
                .onFailure { showStatus(errorText(it), ok = false) }
        }
    }

    /**
     * Новое устройство появляется в списке, когда само завершит вход:
     * смотрим ещё полминуты.
     */
    private suspend fun waitForNewDevice() {
        val before = devices.size

        repeat(WAIT_ROUNDS) {
            delay(WAIT_STEP_MS)
            val found = io { Core.messenger().ownDevices(System.currentTimeMillis()) }.getOrNull() ?: return@repeat
            if (found.size > before) {
                findViewById<View>(R.id.devices_code_panel).isVisible = false
                showStatus(getString(R.string.devices_linked_done), ok = true)
                load()
                // Приём заодно отправляет новому устройству историю за 30
                // дней (ядро, этап 4б), как только оно выложит ключи.
                repeat(RECEIVE_ROUNDS) {
                    delay(WAIT_STEP_MS)
                    io { Core.deviceId?.let { Core.messenger().receiveMessages(it, System.currentTimeMillis()) } }
                }

                return
            }
        }
    }

    private fun confirmUnlink(device: FfiOwnDevice) {
        GasAppDialog(this)
            .title(R.string.devices_unlink_title)
            .message(R.string.devices_unlink_message)
            .secondary()
            .primary(R.string.devices_unlink, tone = GasAppDialog.Tone.Danger, closeOnClick = false) { dialog ->
                dialog.setBusy(true)
                lifecycleScope.launch {
                    val result = io { Core.messenger().unlinkDevice(device.deviceId, System.currentTimeMillis()) }

                    dialog.setBusy(false)
                    result
                        .onSuccess {
                            dialog.dismiss()
                            load()
                        }
                        .onFailure { dialog.showError(errorText(it)) }
                }
            }
            .show()
    }

    private fun errorText(failure: Throwable): String = getString(
        when (failure) {
            is FfiException.PremiumRequired ->
                if (devices.size >= LIMIT) R.string.devices_link_full else R.string.devices_not_primary
            is FfiException.AccountRestricted -> R.string.devices_error_restricted
            is FfiException.Core -> R.string.devices_error_code
            else -> R.string.channels_error_network
        },
    )

    private fun showStatus(text: String, ok: Boolean) {
        status.text = text
        status.setTextColor(getColor(if (ok) R.color.status_ok else R.color.status_error))
        status.isVisible = true
        if (!ok) GasAppToast.show(this, text, GasAppToast.Tone.Error)
    }

    private fun hideStatus() {
        status.isVisible = false
    }

    /** Последние четыре знака идентификатора — чтобы отличить телефоны. */
    private fun shortId(device: FfiOwnDevice): String =
        device.deviceId.replace("-", "").takeLast(SHORT_ID).uppercase()

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private suspend fun <T> io(block: () -> T): Result<T> = withContext(Dispatchers.IO) { runCatching(block) }

    private companion object {
        /** Предел сервера и протокола. */
        const val LIMIT = 5
        const val CODE_DIGITS = 6
        const val SHORT_ID = 4
        const val DIGITS_SP = 40f
        const val DIGITS_SPACING = 0.12f
        /** До двух минут: человек сверяет цифры на новом телефоне. */
        const val WAIT_ROUNDS = 40
        const val WAIT_STEP_MS = 3_000L
        const val RECEIVE_ROUNDS = 10
    }
}

// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.view.HapticFeedbackConstants
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.core.AccountWipe
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.QrDrawable
import uniffi.gasapp.FfiLinkOffer
import uniffi.gasapp.deviceLinkQr

/**
 * Вход с другого телефона (`docs/protocol/MULTI-DEVICE.md`).
 *
 * База уже открыта под новым PIN (экран регистрации). Здесь — QR для
 * основного телефона: он живёт 60 секунд и обновляется сам, ответ
 * основного проверяется каждые две секунды. Пришёл грант — оба
 * телефона показывают шесть цифр; совпали — устройство входит.
 *
 * 🔐 Не завершённый вход стирает базу: она открыта под новым PIN, но
 * аккаунта в ней нет, и при следующем запуске выглядела бы аккаунтом
 * (как у [RestoreActivity]).
 */
class LinkDeviceActivity : AppCompatActivity() {

    private lateinit var qr: ImageView
    private lateinit var waiting: TextView
    private lateinit var status: TextView
    private lateinit var matchButton: GasAppButton

    /** QR и ожидание гранта; перезапускается после отказа. */
    private var loop: Job? = null

    /** Срок текущего QR по `elapsedRealtime`; 0 — кода ещё нет. */
    private var expiresAt = 0L

    /** Вход завершён: уход с экрана больше не стирает базу. */
    private var linked = false

    /** Идёт завершение входа: уходить нельзя — база пишется. */
    private var finishing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_link_device)

        qr = findViewById(R.id.link_qr)
        waiting = findViewById(R.id.link_waiting)
        status = findViewById(R.id.link_status)
        matchButton = findViewById(R.id.link_match)

        findViewById<View>(R.id.link_back).setOnClickListener { leave() }
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() = leave()
            },
        )
        matchButton.setOnClickListener { finishLink() }
        findViewById<GasAppButton>(R.id.link_mismatch).setOnClickListener {
            showStatus(getString(R.string.link_mismatch_done))
            restart()
        }

        restart()
        tick()
    }

    /** Новый QR и ожидание гранта. */
    private fun restart() {
        showQrPage()
        loop?.cancel()
        loop = lifecycleScope.launch { linkLoop() }
    }

    private suspend fun linkLoop() {
        // База закрыта (экран пересоздан после блокировки) — начинать
        // не с чем: назад к регистрации.
        val messenger = runCatching { Core.messenger() }.getOrElse { return leave() }

        while (currentCoroutineContextActive()) {
            expiresAt = 0L
            qr.setImageDrawable(null)
            findViewById<View>(R.id.link_qr_loading).isVisible = true

            val started = withContext(Dispatchers.IO) {
                runCatching {
                    val uri = messenger.startDeviceLink(System.currentTimeMillis())
                    deviceLinkQr(uri)
                }
            }
            val matrix = started.getOrElse {
                showStatus(getString(R.string.link_no_network))
                delay(RETRY_MS)

                return@getOrElse null
            } ?: continue

            if (status.text == getString(R.string.link_no_network)) status.isVisible = false
            findViewById<View>(R.id.link_qr_loading).isVisible = false
            qr.setImageBitmap(QrDrawable.render(matrix, qr.width.takeIf { it > 0 } ?: QR_FALLBACK_PX))
            // На экране — на пару секунд меньше срока: основному телефону
            // нужно успеть проверить код.
            expiresAt = SystemClock.elapsedRealtime() + SHOWN_TTL_MS

            // Прежний ящик слушаем и после срока: ядро основного телефона
            // одобряет код до срока плюс 5 секунд на расхождение часов.
            val listenUntil = expiresAt + LISTEN_GRACE_MS
            while (currentCoroutineContextActive() && SystemClock.elapsedRealtime() < listenUntil) {
                delay(POLL_MS)
                val offer = withContext(Dispatchers.IO) { runCatching { messenger.pollDeviceLink() }.getOrNull() }
                if (offer != null) {
                    showCompare(offer)

                    return
                }
            }
        }
    }

    private suspend fun currentCoroutineContextActive(): Boolean = kotlinx.coroutines.currentCoroutineContext().isActive

    /** Обратный отсчёт под QR — раз в секунду, пока экран жив. */
    private fun tick() {
        lifecycleScope.launch {
            while (isActive) {
                val left = ((expiresAt - SystemClock.elapsedRealtime()) / 1_000L).toInt()
                waiting.text = if (expiresAt == 0L || left <= 0) {
                    getString(R.string.link_preparing)
                } else {
                    getString(R.string.link_waiting, left + 1)
                }
                delay(TICK_MS)
            }
        }
    }

    private fun showQrPage() {
        findViewById<View>(R.id.link_qr_page).isVisible = true
        findViewById<View>(R.id.link_compare_page).isVisible = false
        findViewById<TextView>(R.id.link_intro).setText(R.string.link_intro)
    }

    private fun showCompare(offer: FfiLinkOffer) {
        window.decorView.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
        status.isVisible = false
        findViewById<View>(R.id.link_qr_page).isVisible = false
        findViewById<View>(R.id.link_compare_page).isVisible = true
        findViewById<TextView>(R.id.link_intro).text = getString(R.string.link_compare_intro, offer.username)

        val digits = offer.code.filter(Char::isDigit)
        findViewById<TextView>(R.id.link_digits).apply {
            text = if (digits.length == CODE_DIGITS) "${digits.take(3)} ${digits.takeLast(3)}" else digits
            contentDescription = digits.toList().joinToString(" ")
        }
    }

    private fun finishLink() {
        if (finishing) return
        finishing = true
        matchButton.isLoading = true

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().finishDeviceLink(System.currentTimeMillis())
                        .also { Core.maintainPrekeysNow() }
                }
            }

            matchButton.isLoading = false
            finishing = false

            result
                .onSuccess { account ->
                    linked = true
                    // Устройство запоминается для приёма: конверты
                    // адресуются по нему, а не по аккаунту.
                    Core.rememberDevice(account.deviceId)
                    startActivity(
                        Intent(this@LinkDeviceActivity, ChatListActivity::class.java)
                            .putExtra(OnboardingActivity.EXTRA_DEVICE_ID, account.deviceId),
                    )
                    finish()
                }
                .onFailure {
                    // Грант одноразовый: после отказа — заново, с новым QR.
                    showStatus(getString(R.string.link_failed))
                    restart()
                }
        }
    }

    private fun showStatus(text: String) {
        status.text = text
        status.isVisible = true
    }

    /** Уход с экрана. 🔐 Не завершённый вход стирает базу. */
    private fun leave() {
        if (finishing) return
        loop?.cancel()

        if (!linked) {
            AccountWipe.wipe(this)
            startActivity(Intent(this, OnboardingActivity::class.java))
        }

        finish()
    }

    private companion object {
        const val CODE_DIGITS = 6
        const val SHOWN_TTL_MS = 57_000L
        const val LISTEN_GRACE_MS = 13_000L
        const val POLL_MS = 2_000L
        const val RETRY_MS = 4_000L
        const val TICK_MS = 1_000L
        const val QR_FALLBACK_PX = 640
    }
}

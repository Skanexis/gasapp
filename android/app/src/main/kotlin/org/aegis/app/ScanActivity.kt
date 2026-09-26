// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.EmptyState
import org.aegis.app.ui.QrDecoder

/**
 * Встроенный сканер QR.
 *
 * Нужен в двух местах: добавить контакт по его коду (ключ приходит
 * мимо сервера) и сверить safety number по коду собеседника.
 *
 * # 🔐 Почему свой сканер, а не системная камера
 *
 * Код несёт имя и identity-ключ. Системная камера и Google Lens видели
 * бы его содержимое и вправе отправить кадр в облако. Здесь кадры
 * разбираются в процессе (ZXing, без сети), не сохраняются и не
 * покидают приложение; камера запрашивается только в момент
 * сканирования.
 */
class ScanActivity : AppCompatActivity() {

    /** Что и зачем сканируется — заголовок и подсказка экрана. */
    data class Request(@StringRes val title: Int, @StringRes val hint: Int)

    /** Контракт для вызывающих экранов: запрос → текст кода или `null`. */
    class Contract : ActivityResultContract<Request, String?>() {
        override fun createIntent(context: Context, input: Request): Intent =
            Intent(context, ScanActivity::class.java)
                .putExtra(EXTRA_TITLE, input.title)
                .putExtra(EXTRA_HINT, input.hint)

        override fun parseResult(resultCode: Int, intent: Intent?): String? =
            intent?.getStringExtra(EXTRA_PAYLOAD)?.takeIf { resultCode == Activity.RESULT_OK }
    }

    private lateinit var analysisExecutor: ExecutorService

    /** Первый распознанный код — единственный: повторы кадров не доставляются. */
    private val delivered = AtomicBoolean(false)

    private val cameraPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) startCamera() else showDenied()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)
        setContentView(R.layout.activity_scan)

        analysisExecutor = Executors.newSingleThreadExecutor()

        findViewById<View>(R.id.scan_back).setOnClickListener { finish() }
        findViewById<TextView>(R.id.scan_title).setText(
            intent.getIntExtra(EXTRA_TITLE, R.string.scan_title),
        )
        findViewById<TextView>(R.id.scan_hint).setText(
            intent.getIntExtra(EXTRA_HINT, R.string.scan_hint_contact),
        )

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            cameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        analysisExecutor.shutdown()
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)

        future.addListener(
            {
                val provider = runCatching { future.get() }.getOrNull() ?: return@addListener showDenied()

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = findViewById<PreviewView>(R.id.scan_preview).surfaceProvider
                }

                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                analysis.setAnalyzer(analysisExecutor) { image ->
                    val text = image.use { frame ->
                        val plane = frame.planes[0]
                        val buffer = plane.buffer
                        val bytes = ByteArray(buffer.remaining()).also(buffer::get)

                        QrDecoder.decode(bytes, plane.rowStride, frame.width, frame.height)
                    }

                    if (text != null && delivered.compareAndSet(false, true)) {
                        runOnUiThread { deliver(text) }
                    }
                }

                runCatching {
                    provider.unbindAll()
                    provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                }.onFailure { showDenied() }
            },
            ContextCompat.getMainExecutor(this),
        )
    }

    private fun deliver(text: String) {
        setResult(RESULT_OK, Intent().putExtra(EXTRA_PAYLOAD, text))
        finish()
    }

    /** Камеры нет или она не разрешена: объяснение и путь в настройки. */
    private fun showDenied() {
        val denied = findViewById<View>(R.id.scan_denied)
        denied.visibility = View.VISIBLE

        EmptyState.bind(
            denied,
            icon = R.drawable.ic_qr,
            title = R.string.scan_denied_title,
            body = R.string.scan_denied_body,
            action = R.string.scan_denied_settings,
        ) {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)),
            )
        }
    }

    private companion object {
        const val EXTRA_TITLE = "scan_title"
        const val EXTRA_HINT = "scan_hint"
        const val EXTRA_PAYLOAD = "scan_payload"
    }
}

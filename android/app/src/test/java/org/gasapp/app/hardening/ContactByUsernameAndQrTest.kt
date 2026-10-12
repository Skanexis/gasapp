// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.gasapp.app.ui.QrDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Контакты — по `@имени` и QR, без ссылок.
 *
 * * Встроенный сканер читает код: кадр с QR даёт текст, пустой кадр —
 *   ничего (не «что-то похожее»).
 * * 🔐 Манифест: камера — единственное новое разрешение, а наружу
 *   открыт только стартовый экран. Прежде экран добавления контакта
 *   принимал ссылки `gasapp://` от любого приложения; ссылок больше нет,
 *   и эта дверь закрыта.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ContactByUsernameAndQrTest {

    /** Рисует QR в яркостный кадр, как его отдаёт камера (с полем по краям). */
    private fun frameWith(text: String, side: Int = 400): ByteArray {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, side, side)
        return ByteArray(side * side) { index ->
            if (matrix[index % side, index / side]) 0 else 0xFF.toByte()
        }
    }

    @Test
    fun the_scanner_reads_a_contact_code() {
        val payload = "gasapp://contact/QBYTIJWSRBVQGWUDJ2ZGWBVPV5KOK.7RD5UIKFSTF?name=anna"

        assertEquals(payload, QrDecoder.decode(frameWith(payload), 400, 400, 400))
    }

    @Test
    fun the_scanner_reads_a_safety_number_code() {
        val digits = "680854947581425400158725282127707981591917116295386117957675"

        assertEquals(digits, QrDecoder.decode(frameWith(digits), 400, 400, 400))
    }

    @Test
    fun an_empty_frame_gives_nothing() {
        assertNull(QrDecoder.decode(ByteArray(400 * 400) { 0x7F }, 400, 400, 400))
    }

    @Test
    fun a_truncated_frame_is_refused_not_read_past_its_end() {
        assertNull(QrDecoder.decode(ByteArray(100), 400, 400, 400))
    }

    /** 🔐 Разрешения приложения — ровно эти; новое — только осознанно. */
    @Test
    fun permissions_are_exactly_the_expected_ones() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val requested = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
            .requestedPermissions
            .orEmpty()
            .filter { it.startsWith("android.permission.") }
            .toSet()

        assertEquals(
            setOf(
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.VIBRATE",
                "android.permission.WAKE_LOCK",
                // Уведомления «есть новое» (ADR-040): показ и восстановление
                // фоновой проверки после перезагрузки.
                "android.permission.POST_NOTIFICATIONS",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                // Только для встроенного сканера QR, запрашивается в момент сканирования.
                "android.permission.CAMERA",
                // Добавляет androidx.biometric: вход по отпечатку на старых версиях.
                "android.permission.USE_FINGERPRINT",
            ),
            requested - setOf("android.permission.USE_BIOMETRIC"),
        )
    }

    /** 🔐 Снаружи открыт только стартовый экран — ссылок gasapp:// больше нет. */
    @Test
    fun only_the_launcher_is_exported() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val activities = context.packageManager
            .getPackageInfo(context.packageName, PackageManager.GET_ACTIVITIES)
            .activities
            .orEmpty()

        val exported = activities
            .filter { it.exported && it.name.startsWith("org.gasapp.app.") }
            .map { it.name.substringAfterLast('.') }

        assertTrue("наружу открыты лишние экраны: $exported", exported == listOf("LockActivity"))
    }
}

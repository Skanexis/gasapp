// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisTextField
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import uniffi.aegis.FfiException

/**
 * Онбординг: регистрация первого аккаунта.
 *
 * 🔐 Предупреждение об отсутствии аудита показывается **до** кнопки
 * и тем же кеглем, что и остальной текст (раздел 21 плана). Мессенджер,
 * обещающий защиту, которую не проверял никто посторонний, обязан
 * сказать об этом до того, как пользователь начнёт ему доверять.
 */
class OnboardingActivity : AppCompatActivity() {

    private lateinit var username: AegisTextField
    private lateinit var pin: AegisTextField
    private lateinit var error: TextView
    private lateinit var progress: ProgressBar
    private lateinit var progressLabel: TextView
    private lateinit var createButton: AegisButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_onboarding)

        username = findViewById(R.id.onboarding_username)
        pin = findViewById(R.id.onboarding_pin)
        error = findViewById(R.id.onboarding_error)
        progress = findViewById(R.id.onboarding_progress)
        progressLabel = findViewById(R.id.onboarding_progress_label)
        createButton = findViewById(R.id.onboarding_create)

        createButton.setOnClickListener { register() }
    }

    private fun register() {
        val name = username.text?.toString()?.trim().orEmpty()
        val pinValue = pin.text?.toString().orEmpty()

        if (name.length < MIN_USERNAME_LENGTH) {
            showError(getString(R.string.onboarding_error_short))

            return
        }

        if (pinValue.length < MIN_PIN_LENGTH) {
            showError(getString(R.string.onboarding_error_pin_short))

            return
        }

        setWorking(true)

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    // 🔐 Ключ хранилища выводится из PIN через Argon2id
                    // и связывается с секретом, не покидающим устройство
                    // (Core.unlock). Занимает около секунды и идёт
                    // в фоновом потоке.
                    //
                    // Цена этой секунды — то, что снятый с телефона файл
                    // базы не перебирается: одного PIN для ключа мало.
                    //
                    // Общий экземпляр: второй открыл бы ту же базу
                    // повторно, и состояния Double Ratchet разошлись бы.
                    Core.unlock(this@OnboardingActivity, pinValue)
                        .register(name, System.currentTimeMillis())
                }
            }

            setWorking(false)

            result
                .onSuccess { account ->
                    // Устройство запоминается для приёма: конверты
                    // адресуются по нему, а не по аккаунту.
                    Core.rememberDevice(account.deviceId)

                    startActivity(
                        Intent(this@OnboardingActivity, ChatListActivity::class.java)
                            .putExtra(EXTRA_DEVICE_ID, account.deviceId),
                    )
                    finish()
                }
                .onFailure { failure ->
                    // Текст ошибки ядра намеренно неинформативен, поэтому
                    // показывается собственная строка. Различать «имя
                    // занято» и «сервер недоступен» здесь можно только
                    // по типу исключения.
                    showError(
                        if (failure is FfiException) {
                            getString(R.string.onboarding_error_network)
                        } else {
                            getString(R.string.ffi_error)
                        },
                    )
                }
        }
    }

    private fun setWorking(working: Boolean) {
        // Кнопка блокируется на время подбора proof-of-work: повторное
        // нажатие запустило бы вторую регистрацию поверх первой.
        createButton.isEnabled = !working
        username.isEnabled = !working

        val visibility = if (working) View.VISIBLE else View.GONE
        progress.visibility = visibility
        progressLabel.visibility = visibility

        if (working) {
            error.visibility = View.INVISIBLE
        }
    }

    private fun showError(message: String) {
        error.text = message
        error.visibility = View.VISIBLE
    }

    /**
     * Адрес сервера.
     *
     * Пока задан константой сборки: настройка адреса появится вместе
     * с экраном выбора сервера. Значение вынесено в BuildConfig, чтобы
     * отладочная и релизная сборки не могли случайно указать на один
     * и тот же сервер.
     */
    private fun serverUrl(): String = BuildConfig.AEGIS_SERVER_URL

    companion object {
        /** Идентификатор устройства для последующих запросов. */
        const val EXTRA_DEVICE_ID = "device_id"

        /**
         * Минимальная длина имени.
         *
         * Короткие имена вычерпываются перебором, и злоумышленник смог
         * бы занять их все до появления настоящих пользователей.
         */
        private const val MIN_USERNAME_LENGTH = 3

        /**
         * Минимальная длина PIN.
         *
         * Совпадает с проверкой в ядре: шесть символов вместе
         * с растягиванием Argon2id делают перебор изъятого устройства
         * делом лет, а не часов.
         */
        private const val MIN_PIN_LENGTH = 6

        /** Размер ключа SQLCipher. */
        private const val DATABASE_KEY_SIZE = 32
    }
}

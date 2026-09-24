// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import uniffi.aegis.validateRecoveryKey

/**
 * Восстановление из резервной копии.
 *
 * # Порядок
 *
 * Выбрать файлы цепочки → ввести ключ → восстановить. Кнопка
 * восстановления недоступна, пока не сделано и то, и другое: нажатие,
 * заведомо кончающееся ошибкой, — это не подсказка, а раздражение.
 *
 * # 🔐 Про цепочку
 *
 * Файлы применяются в том порядке, в каком выбраны: сначала полный
 * снимок, затем инкременты. Целостность цепочки проверяется в ядре
 * по SHA-256 каждого звена, и разрыв означает отказ **целиком**.
 * Восстановить «сколько получилось» нельзя: человек решил бы,
 * что копия цела, и стёр бы остальное.
 *
 * # Про ключ
 *
 * Контрольная сумма проверяется прямо при вводе — то есть об опечатке
 * сообщается мгновенно, до нескольких секунд Argon2id. Успех проверки
 * означает «строка выглядит как ключ», а не «этот ключ открывает
 * вашу копию»: второе выясняется только попыткой.
 */
class RestoreActivity : AppCompatActivity() {

    /** Выбранные файлы цепочки в порядке применения. */
    private val chosen = mutableListOf<Uri>()

    /**
     * Режим возвращения аккаунта (с экрана регистрации): вместе
     * с перепиской возвращается аккаунт с прежним именем.
     */
    private val recovering by lazy { intent.getBooleanExtra(EXTRA_RECOVER_ACCOUNT, false) }

    /** Аккаунт возвращён: уход с экрана больше не стирает базу. */
    private var recovered = false

    /**
     * Выбор файлов копии.
     *
     * Разрешён множественный выбор: цепочка из снимка и инкрементов
     * лежит несколькими файлами, и просить их по одному значило бы
     * заставить человека повторять диалог столько раз, сколько дней
     * он делал копии.
     */
    private val pickArchives = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts
            .StartActivityForResult(),
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult

        chosen.clear()

        val data = result.data
        val clip = data?.clipData

        if (clip != null) {
            for (index in 0 until clip.itemCount) {
                chosen.add(clip.getItemAt(index).uri)
            }
        } else {
            data?.data?.let { chosen.add(it) }
        }

        render()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_restore)

        findViewById<ImageView>(R.id.restore_back).setOnClickListener { leave() }

        if (recovering) {
            findViewById<TextView>(R.id.restore_title).setText(R.string.recover_title)
            findViewById<TextView>(R.id.restore_intro).setText(R.string.recover_intro)
        }

        onBackPressedDispatcher.addCallback(
            this,
            object : androidx.activity.OnBackPressedCallback(true) {
                override fun handleOnBackPressed() = leave()
            },
        )
        findViewById<AegisButton>(R.id.restore_pick).setOnClickListener { pickFiles() }
        findViewById<AegisButton>(R.id.restore_confirm).setOnClickListener { restore() }

        // Отклик о форме ключа при каждом изменении: контрольная сумма
        // считается мгновенно, и ждать нажатия незачем.
        findViewById<EditText>(R.id.restore_key).addTextChangedListener(
            object : TextWatcher {
                override fun afterTextChanged(s: Editable?) = render()

                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit

                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            },
        )

        render()
    }

    private fun pickFiles() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }

        pickArchives.launch(intent)
    }

    private fun render() {
        val entered = findViewById<EditText>(R.id.restore_key).text.toString()
        val keyLooksValid = entered.isNotBlank() && validateRecoveryKey(entered)

        findViewById<TextView>(R.id.restore_files).text = when (chosen.size) {
            0 -> getString(R.string.restore_no_files)
            else -> getString(R.string.restore_files_chosen, chosen.size)
        }

        findViewById<TextView>(R.id.restore_key_state).setText(
            when {
                entered.isBlank() -> R.string.restore_key_empty
                keyLooksValid -> R.string.restore_key_ok
                // 🔐 Именно контрольная сумма и отсеивает это до
                // дорогого растягивания.
                else -> R.string.restore_key_invalid
            },
        )

        findViewById<AegisButton>(R.id.restore_confirm).isEnabled =
            keyLooksValid && chosen.isNotEmpty()
    }

    private fun restore() {
        val key = findViewById<EditText>(R.id.restore_key).text.toString()
        val button = findViewById<AegisButton>(R.id.restore_confirm)

        button.isLoading = true

        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val links = chosen.map { uri ->
                        contentResolver.openInputStream(uri)?.use { it.readBytes() }
                            ?: error("файл не читается")
                    }

                    if (recovering) {
                        // 🔐 Аккаунт — с прежним именем, на новой identity:
                        // ключ восстановления аккаунта из копии подписывает
                        // перепривязку (см. `Client::recover_account`).
                        val back = Core.messenger().recoverAccount(
                            recoveryKey = key,
                            links = links,
                            nowMillis = System.currentTimeMillis(),
                        )
                        Core.rememberDevice(back.account.deviceId)
                        Core.maintainPrekeysNow()
                        back.restore
                    } else {
                        Core.messenger().restoreBackup(
                            recoveryKey = key,
                            links = links,
                            nowMillis = System.currentTimeMillis(),
                        )
                    }
                }
            }

            button.isLoading = false

            outcome.onSuccess { restored ->
                recovered = true
                showStatus(getString(R.string.restore_done, restored.applied.toInt()))

                // 🔐 Объяснение смены ключа безопасности — обязательный
                // шаг, а не любезность: собеседники увидят её как
                // возможную подмену (раздел 12.5).
                if (restored.identityChanged) {
                    startActivity(
                        Intent(this@RestoreActivity, IdentityChangedActivity::class.java)
                            .putExtra(
                                IdentityChangedActivity.EXTRA_APPLIED,
                                restored.applied.toInt(),
                            ),
                    )
                    finish()
                }
            }.onFailure {
                button.isError = true
                // Причина не уточняется: «не тот ключ» и «цепочка
                // разорвана» различать здесь нечем, а гадать вслух
                // хуже, чем сказать честно.
                showStatus(
                    getString(if (recovering) R.string.recover_failed else R.string.restore_failed),
                )
            }
        }
    }

    /**
     * Уход с экрана. 🔐 Не завершённое возвращение аккаунта стирает
     * базу: она открыта под новым PIN, но аккаунта в ней нет, и при
     * следующем запуске она выглядела бы аккаунтом.
     */
    private fun leave() {
        if (recovering && !recovered) {
            AccountWipe.wipe(this)
            startActivity(Intent(this, OnboardingActivity::class.java))
        }

        finish()
    }

    private fun showStatus(text: String) {
        findViewById<TextView>(R.id.restore_status).apply {
            this.text = text
            visibility = View.VISIBLE
        }
    }

    companion object {
        /** Режим возвращения аккаунта: `true` — с экрана регистрации. */
        const val EXTRA_RECOVER_ACCOUNT = "recover_account"
    }
}

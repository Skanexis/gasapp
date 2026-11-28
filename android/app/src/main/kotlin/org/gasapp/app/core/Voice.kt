// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.content.Context
import android.media.MediaDataSource
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.os.Handler
import android.os.Looper
import java.io.File

/**
 * Запись голосового: AAC 24 кГц моно, как на iOS.
 *
 * 🔐 Запись идёт во временный файл в кеше приложения и стирается сразу
 * после чтения: на телефоне голосового не остаётся — оно уходит под
 * сквозным шифрованием, как любое вложение. Метаданные контейнера (время
 * в заголовках) вычищает ядро перед шифрованием.
 *
 * Аудит 2026-11-28: запись, брошенная на середине (экран свернули,
 * приложение заперлось, процесс убит), оставляла `voice-*.m4a` в кеше
 * открытым звуком. Теперь запись отменяется в `onStop` экрана и при
 * запирании ([cancelActive]), а остатки прошлых сеансов стираются при
 * открытии хранилища ([sweep]).
 */
class VoiceRecorder(private val context: Context) {
    private var recorder: MediaRecorder? = null
    private var file: File? = null
    private var startedAt = 0L
    private val samples = ArrayList<Int>()
    private val handler = Handler(Looper.getMainLooper())

    /** Идёт ли запись. */
    val recording: Boolean get() = recorder != null

    /** Сколько записано, миллисекунды. */
    val elapsedMillis: Long get() = if (recording) System.currentTimeMillis() - startedAt else 0L

    private val meter = object : Runnable {
        override fun run() {
            val active = recorder ?: return
            samples.add(runCatching { active.maxAmplitude }.getOrDefault(0))
            handler.postDelayed(this, METER_MS)
        }
    }

    /** Начать запись; не вышло (нет микрофона, занят) — `false`. */
    fun start(): Boolean {
        if (recording) return true
        val target = File.createTempFile(FILE_PREFIX, FILE_SUFFIX, context.cacheDir)
        val created = runCatching {
            newRecorder().apply {
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
                setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
                setAudioSamplingRate(SAMPLE_RATE)
                setAudioChannels(1)
                setAudioEncodingBitRate(BIT_RATE)
                setMaxDuration(MAX_MILLIS.toInt())
                setOutputFile(target.absolutePath)
                prepare()
                start()
            }
        }.getOrNull()
        if (created == null) {
            target.delete()
            return false
        }
        recorder = created
        file = target
        active = this
        samples.clear()
        startedAt = System.currentTimeMillis()
        handler.postDelayed(meter, METER_MS)
        return true
    }

    /**
     * Закончить: звук, длительность и огибающая громкости (до 100 точек).
     * Короче полусекунды — случайное касание: `null`.
     */
    fun finish(): Voice? {
        val duration = elapsedMillis
        val target = file
        stop()
        return try {
            if (duration < MIN_MILLIS || target == null) null
            else Voice(target.readBytes(), duration.coerceAtMost(MAX_MILLIS), waveform(samples, POINTS))
        } catch (_: Exception) {
            null
        } finally {
            target?.delete()
        }
    }

    /** Передумали — запись стирается. */
    fun cancel() {
        val target = file
        stop()
        target?.delete()
    }

    @Suppress("DEPRECATION")
    private fun newRecorder(): MediaRecorder =
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) MediaRecorder(context) else MediaRecorder()

    private fun stop() {
        handler.removeCallbacks(meter)
        runCatching { recorder?.stop() }
        runCatching { recorder?.release() }
        recorder = null
        file = null
        if (active === this) active = null
    }

    /** Записанное голосовое. */
    class Voice(val audio: ByteArray, val durationMillis: Long, val waveform: ByteArray)

    companion object {
        private const val SAMPLE_RATE = 24_000
        private const val BIT_RATE = 32_000
        private const val METER_MS = 50L
        private const val MIN_MILLIS = 500L
        private const val MAX_MILLIS = 600_000L
        private const val POINTS = 100

        /** Префикс и расширение временных файлов записи. */
        private const val FILE_PREFIX = "voice-"
        private const val FILE_SUFFIX = ".m4a"

        /** Идущая запись — одна на приложение (микрофон один). */
        @Volatile
        private var active: VoiceRecorder? = null

        /** 🔐 Отменить идущую запись, где бы она ни шла: при запирании. */
        fun cancelActive() {
            active?.cancel()
        }

        /**
         * 🔐 Стереть записи, оставшиеся от прошлых сеансов (процесс убит
         * посреди записи). Вызывается при открытии хранилища и при
         * удалении аккаунта; идущую запись не трогает.
         */
        fun sweep(context: Context): Int {
            val current = active?.file
            var removed = 0
            context.cacheDir.listFiles()?.forEach { file ->
                if (file.isFile && file.name.startsWith(FILE_PREFIX) && file.name.endsWith(FILE_SUFFIX) &&
                    file != current && runCatching { file.delete() }.getOrDefault(false)
                ) {
                    removed += 1
                }
            }
            return removed
        }

        /** Сжать замеры громкости (0…32767) до `points` значений 0…255. */
        fun waveform(samples: List<Int>, points: Int): ByteArray {
            if (samples.isEmpty()) return ByteArray(0)
            val count = minOf(points, samples.size)
            val step = samples.size.toDouble() / count
            return ByteArray(count) { index ->
                val from = (index * step).toInt()
                val to = maxOf(from + 1, ((index + 1) * step).toInt()).coerceAtMost(samples.size)
                val peak = samples.subList(from, to).maxOrNull() ?: 0
                (peak.coerceIn(0, 32_767) * 255 / 32_767).toByte()
            }
        }
    }
}

/**
 * Проигрыватель голосовых — из памяти, без временного файла: звук
 * расшифрован ядром и на диск не пишется. Один на приложение: новое
 * голосовое останавливает прежнее.
 */
object VoicePlayer {
    private var player: MediaPlayer? = null

    /** Что играет: описание вложения. */
    var playing: ByteArray? = null
        private set

    /** Играть; то же самое ещё раз — остановить. Не вышло — `false`. */
    fun toggle(key: ByteArray, audio: ByteArray, onDone: () -> Unit = {}): Boolean {
        if (playing?.contentEquals(key) == true) {
            stop()
            return true
        }
        stop()
        val created = runCatching {
            MediaPlayer().apply {
                setDataSource(BytesSource(audio))
                setOnCompletionListener {
                    stop()
                    onDone()
                }
                prepare()
                start()
            }
        }.getOrNull() ?: return false
        player = created
        playing = key
        return true
    }

    fun stop() {
        runCatching { player?.stop() }
        runCatching { player?.release() }
        player = null
        playing = null
    }

    private class BytesSource(private val bytes: ByteArray) : MediaDataSource() {
        override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
            if (position >= bytes.size) return -1
            val count = minOf(size.toLong(), bytes.size - position).toInt()
            System.arraycopy(bytes, position.toInt(), buffer, offset, count)
            return count
        }

        override fun getSize(): Long = bytes.size.toLong()

        override fun close() = Unit
    }
}

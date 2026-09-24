// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.app.Activity
import android.app.Dialog
import android.os.Build
import android.view.View
import android.view.Window
import android.view.WindowManager
import java.io.File
import org.aegis.app.BuildConfig

/**
 * Защита окна экрана: снимки и накрывающие окна.
 *
 * # Что делает FLAG_SECURE
 *
 * 🔐 Запрещает системе делать снимок окна: скриншот не получится,
 * содержимое не попадёт в переключатель задач и не уйдёт на внешний
 * дисплей при трансляции.
 *
 * Прежде флаг стоял только на экране блокировки — то есть защищал
 * пустой экран ввода PIN, а переписку оставлял открытой. Снимок
 * переключателя задач показывал последний открытый чат любому, кто
 * взял телефон в руки.
 *
 * # Чего он не делает
 *
 * Не мешает сфотографировать экран другим телефоном и не ограничивает
 * собеседника — тот видел сообщение и мог его сохранить. Обещать
 * больше, чем платформа даёт, опаснее, чем не обещать: пользователь
 * строит поведение на защите, которой нет.
 *
 * # Почему при создании экрана
 *
 * Флаг снимается и ставится на лету, но между двумя состояниями
 * система успевает снять кадр. Применение при создании даёт
 * предсказуемое правило: настройка действует со следующего открытия
 * экрана.
 *
 * # Защита от накрывающих окон
 *
 * 🔐 Отдельная мера — [blockObscuredTouches], MASVS PLATFORM-3.
 * Приложение, получившее разрешение рисовать поверх других, может
 * положить прозрачное окно с дырой поверх чужого экрана: человек видит
 * «Отмена», нажимает и попадает по «Подтвердить» под ней. Классическая
 * цель такой подмены — ровно то, что здесь и защищается: подтверждение
 * ключа, открытие хранилища файлов, ввод PIN.
 *
 * `filterTouchesWhenObscured` заставляет платформу отбрасывать касания,
 * пришедшие в накрытое окно.
 *
 * ⚠️ Мера применяется не ко всем экранам, и это решение. Накрывающим
 * окном пользуются и вспомогательные технологии; включённая повсюду
 * фильтрация ломала бы часть из них, а полное покрытие accessibility —
 * такое же требование M8, как и это. Поэтому фильтрация стоит там, где
 * ошибочное нажатие необратимо или выдаёт доступ: PIN, хранилище
 * файлов, ключ восстановления, сверка ключей. На экранах переписки
 * её нет.
 *
 * # Защита от чтения экрана службами специальных возможностей
 *
 * 🔐 Третья мера — [hideFromNonToolAccessibility]. Банковские трояны
 * для Android читают чужие экраны через службы специальных
 * возможностей: разрешение выпрашивается под любым предлогом, и
 * дальше служба видит каждое сообщение и каждую цифру PIN. Снимки
 * экрана и фильтр касаний от этого не защищают — служба читает
 * дерево элементов, а не пиксели.
 *
 * С Android 14 окно можно пометить как чувствительное: его содержимое
 * видят только службы, объявившие себя инструментами доступности
 * (`isAccessibilityTool` — TalkBack, Switch Access, экранные лупы;
 * Google Play проверяет это объявление). Прочие получают пустое окно.
 * Людям, которые пользуются чтением с экрана, ничего не меняется —
 * поэтому, в отличие от фильтра касаний, мера стоит на всех экранах.
 *
 * ⚠️ На Android 13 и ниже такой пометки нет, и защиты тоже.
 */
object SecureWindow {

    /**
     * Применяет настройку к окну экрана.
     *
     * Вызывается из `onCreate` **до** `setContentView`: после отрисовки
     * первый кадр уже мог попасть в снимок.
     *
     * 🔐 При недоступном хранилище флаг ставится. Отказ читать
     * настройку — не повод показывать переписку: неизвестное состояние
     * трактуется в пользу защиты.
     */
    fun apply(activity: Activity) {
        hideFromNonToolAccessibility(activity.window)

        val block = runCatching {
            Core.messenger().settingBool(Settings.BLOCK_SCREENSHOTS, true)
        }.getOrDefault(true)

        if (block) {
            setSecure(activity)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    /**
     * Ставит `FLAG_SECURE` независимо от настройки.
     *
     * 🔐 Для экранов, где показывается не переписка, а ключи и файлы
     * хранилища. Человек, выключивший блокировку снимков ради чатов,
     * не имел в виду «показывать ключ восстановления в переключателе
     * задач».
     *
     * Четыре экрана делали это одинаковым `setFlags` у себя; вынесено
     * сюда, чтобы к флагу можно было добавить [blockObscuredTouches]
     * в одном месте, а не в четырёх.
     */
    fun applyAlways(activity: Activity) {
        setSecure(activity)
        blockObscuredTouches(activity)
        hideFromNonToolAccessibility(activity.window)
    }

    /**
     * 🔐 Содержимое окна — только инструментам доступности (Android 14+).
     *
     * Ставится на `decorView`: пометка наследуется потомками, и корня
     * достаточно. Подробности — в описании объекта.
     */
    fun hideFromNonToolAccessibility(window: Window?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            window?.decorView?.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
    }

    /**
     * 🔐 Отбрасывает касания, пришедшие в накрытое чужим окном окно.
     *
     * Ставится на `decorView`: `ViewGroup.dispatchTouchEvent` проверяет
     * флаг до того, как отдать событие детям, поэтому корня достаточно
     * и перечислять кнопки не нужно.
     *
     * Видимого эффекта при обычной работе нет — отброшенное касание
     * выглядит как непопадание по кнопке. Это осознанный выбор в пользу
     * отказа: при накрытом окне приложение не знает, куда человек
     * на самом деле смотрел.
     */
    fun blockObscuredTouches(activity: Activity) {
        activity.window.decorView.filterTouchesWhenObscured = true
    }

    /**
     * 🔐 Диалог наследует запрет снимков от своего экрана.
     *
     * Диалог — отдельное окно, и `FLAG_SECURE` экрана на него
     * не переходит. Прежде ни один диалог приложения флага не ставил:
     * снимок экрана и превью в переключателе задач показывали их
     * содержимое — имена файлов хранилища, имена собеседников, поля
     * ввода, — даже когда сам экран был защищён.
     *
     * Вызывается до `show()`: флаг, поставленный после, опоздал бы
     * на первый кадр.
     */
    fun inherit(dialog: Dialog, host: Activity) {
        hideFromNonToolAccessibility(dialog.window)

        val flags = host.window.attributes.flags

        if (flags and WindowManager.LayoutParams.FLAG_SECURE != 0) {
            dialog.window?.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
    }

    /**
     * Ставит `FLAG_SECURE` на диалог независимо от настройки — для
     * диалогов, где вводится ключ восстановления.
     */
    fun always(dialog: Dialog) {
        hideFromNonToolAccessibility(dialog.window)

        dialog.window?.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
    }

    /**
     * Снимки экрана для работы над дизайном — **только в отладочной сборке**.
     *
     * Включается файлом, который можно создать лишь через
     * `adb shell run-as <пакет> touch no_backup/design-capture`: `run-as`
     * работает только для debuggable-сборки. В релизе `BuildConfig.DEBUG`
     * — константа `false`, и R8 вырезает проверку вместе с чтением файла.
     */
    private fun designCaptureAllowed(activity: Activity): Boolean =
        BuildConfig.DEBUG && File(activity.noBackupFilesDir, DESIGN_CAPTURE_FLAG).exists()

    /** Файл-флаг отладочных снимков экрана (см. [designCaptureAllowed]). */
    private const val DESIGN_CAPTURE_FLAG = "design-capture"

    private fun setSecure(activity: Activity) {
        if (designCaptureAllowed(activity)) {
            return
        }

        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
    }
}

/**
 * Показывает диалог, унаследовавший запрет снимков от экрана.
 *
 * 🔐 Флаг ставится **до** показа (см. [SecureWindow.inherit]).
 */
fun androidx.appcompat.app.AlertDialog.Builder.showSecure(
    host: Activity,
): androidx.appcompat.app.AlertDialog = create().also {
    SecureWindow.inherit(it, host)
    it.show()
}

/** То же для платформенного `AlertDialog`. */
fun android.app.AlertDialog.Builder.showSecure(host: Activity): android.app.AlertDialog =
    create().also {
        SecureWindow.inherit(it, host)
        it.show()
    }

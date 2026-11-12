// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Строки интерфейса: русский, английский и итальянский, как у Android
/// (`values-ru`, `values`, `values-it`).
///
/// Язык — тот, что iOS выбрала для приложения из его переводов (`en`,
/// `ru`, `it` в `Resources/*.lproj`): язык телефона или выбранный в
/// «Настройки → GasApp → Язык». Любой другой язык телефона — английский.
/// По тому же выбору iOS переводит и свои меню («Вставить», «Вырезать»),
/// поэтому язык приложения и системных подсказок всегда совпадает.
///
/// Тройками в коде, а не каталогом строк: строка без перевода не
/// соберётся, а не покажет ключ вместо текста.
enum L10n {
    enum Language { case en, ru, it }

    static let language: Language = {
        let chosen = Bundle.main.preferredLocalizations.first ?? "en"
        if chosen.hasPrefix("ru") { return .ru }
        if chosen.hasPrefix("it") { return .it }
        return .en
    }()

    static var isRussian: Bool { language == .ru }

    @inline(__always)
    static func t(_ ru: String, _ en: String, _ it: String) -> String {
        switch language {
        case .ru: ru
        case .it: it
        case .en: en
        }
    }
}

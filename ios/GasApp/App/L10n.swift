// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Строки интерфейса: русский и английский, как у Android
/// (`values-ru` и `values`). Выбор — по первому языку системы.
///
/// Парами в коде, а не каталогом строк: так строка без перевода не
/// соберётся, а не покажет ключ вместо текста.
enum L10n {
    static let isRussian: Bool = {
        let language = Locale.preferredLanguages.first ?? "en"
        return language.hasPrefix("ru") || language.hasPrefix("uk") || language.hasPrefix("be")
    }()

    @inline(__always)
    static func t(_ ru: String, _ en: String) -> String { isRussian ? ru : en }
}

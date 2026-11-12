// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// Шрифты Night Camp — те же, что на Android (DESIGN.md, «Typography»).
///
/// * **Rubik Black** — вывески: заголовок экрана, крупный заголовок,
///   пустые экраны, логотип.
/// * **Rubik Bold** — надписи на кнопках.
/// * **Inter** — всё, что человек читает: сообщения, записи, подписи,
///   строки списков и настроек.
/// * Моноширинный — то, что сверяют по знаку (ключи, коды, ссылки):
///   системный, как и прежде.
///
/// Размеры масштабируются системной настройкой «Размер текста»
/// (`relativeTo:`): шрифт свой, а доступность — как у системного.
enum GasFont {
    /// Вывеска: Rubik Black.
    static func display(_ size: CGFloat, relativeTo style: Font.TextStyle = .title) -> Font {
        .custom("GasAppRubik-Black", size: size, relativeTo: style)
    }

    /// Надпись на кнопке: Rubik Bold.
    static func sign(_ size: CGFloat, relativeTo style: Font.TextStyle = .headline) -> Font {
        .custom("GasAppRubik-Bold", size: size, relativeTo: style)
    }

    /// Текст для чтения: Inter нужной насыщенности.
    static func text(_ size: CGFloat, _ weight: Font.Weight = .regular,
                     relativeTo style: Font.TextStyle = .body) -> Font {
        .custom(interName(weight), size: size, relativeTo: style)
    }

    static func interName(_ weight: Font.Weight) -> String {
        switch weight {
        case .bold, .heavy, .black: return "GasAppInter-Bold"
        case .semibold, .medium: return "GasAppInter-SemiBold"
        default: return "GasAppInter-Regular"
        }
    }

    /// Шрифты системных панелей (заголовок навигации, вкладки) — один раз
    /// при запуске: SwiftUI сам их не берёт из окружения.
    @MainActor
    static func applyToSystemBars() {
        let nav = UINavigationBarAppearance()
        nav.configureWithDefaultBackground()
        let white = UIColor(red: 0.96, green: 0.96, blue: 1, alpha: 1)
        if let large = UIFont(name: "GasAppRubik-Black", size: 32) {
            nav.largeTitleTextAttributes = [.font: UIFontMetrics(forTextStyle: .largeTitle).scaledFont(for: large),
                                            .foregroundColor: white]
        }
        if let inline = UIFont(name: "GasAppInter-SemiBold", size: 17) {
            nav.titleTextAttributes = [.font: UIFontMetrics(forTextStyle: .headline).scaledFont(for: inline),
                                       .foregroundColor: white]
        }
        UINavigationBar.appearance().standardAppearance = nav
        UINavigationBar.appearance().scrollEdgeAppearance = nav
        UINavigationBar.appearance().compactAppearance = nav

        if let tab = UIFont(name: "GasAppInter-SemiBold", size: 11) {
            UITabBarItem.appearance().setTitleTextAttributes([.font: tab], for: .normal)
        }
    }
}

import SwiftUI

@main
struct GasAppApp: App {
    var body: some Scene {
        WindowGroup {
            #if GASAPP_GALLERY
            // Сборка проверки на Mac (tools/mac-check.sh): экран выбирается
            // переменной GASAPP_SCREEN, чтобы снять снимок каждого.
            ScreenGallery.root()
            #else
            ContentView()
            #endif
        }
    }
}

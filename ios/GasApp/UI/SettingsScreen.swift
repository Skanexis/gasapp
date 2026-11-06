// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Настройки: аккаунт, сеть, защита, документы, удаление аккаунта.
///
/// Удаление аккаунта — из самого приложения: этого требует App Store
/// (Guideline 5.1.1(v)), и того же ждёт Google Play.
struct SettingsScreen: View {
    @Environment(AppModel.self) private var model

    @State private var username = ""
    @State private var viaTor = false
    @State private var wipeAfterTen = PinAttempts.wipeEnabled
    @State private var torStatus = ""
    @State private var confirmDelete = false
    @State private var deleting = false
    @State private var deletion: FfiAccountDeletion?
    @State private var error: String?

    var body: some View {
        Form {
            Section(L10n.t("Аккаунт", "Account")) {
                LabeledContent(L10n.t("Имя", "Username"), value: username.isEmpty ? "—" : "@\(username)")
                Button(L10n.t("Заблокировать сейчас", "Lock now")) { model.lock() }
            }

            Section {
                Toggle(L10n.t("Через Tor", "Use Tor"), isOn: $viaTor)
                    .onChange(of: viaTor) { _, value in setTor(value) }
                if viaTor && !torStatus.isEmpty {
                    Text(torStatus).font(.system(size: 13)).foregroundStyle(GasAppColor.textTertiary)
                }
            } header: {
                Text(L10n.t("Сеть", "Network"))
            } footer: {
                Text(L10n.t("Напрямую сервер видит ваш IP-адрес. Через Tor — нет, но медленнее.",
                            "Directly, the server sees your IP address. Via Tor it doesn’t, but it’s slower."))
            }

            Section {
                Toggle(L10n.t("Стереть всё после 10 неверных PIN", "Erase everything after 10 wrong PINs"),
                       isOn: $wipeAfterTen)
                    .onChange(of: wipeAfterTen) { _, value in PinAttempts.wipeEnabled = value }
            } header: {
                Text(L10n.t("Защита", "Security"))
            } footer: {
                Text(L10n.t("Защищает от перебора, но ребёнок, играющий с телефоном, может всё стереть.",
                            "Stops guessing, but a child playing with the phone could erase everything."))
            }

            Section(L10n.t("Документы", "Documents")) {
                link(L10n.t("Политика конфиденциальности", "Privacy policy"), "privacy/")
                link(L10n.t("Условия использования", "Terms of use"), "terms/")
                link(L10n.t("Правила сообщества", "Community guidelines"), "community-guidelines/")
                link(L10n.t("Поддержка", "Support"), "support/")
            }

            Section {
                Button(role: .destructive) { confirmDelete = true } label: {
                    if deleting { ProgressView() } else { Text(L10n.t("Удалить аккаунт", "Delete account")) }
                }
                .disabled(deleting)
                if let error { Text(error).foregroundStyle(GasAppColor.error) }
            } footer: {
                Text(L10n.t("Аккаунт удаляется на сервере, переписка — с этого телефона. Вернуть нельзя.",
                            "The account is deleted on the server and messages from this phone. This can’t be undone."))
            }

            Section {
                LabeledContent(L10n.t("Версия ядра", "Core version"), value: coreVersion())
            }
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Настройки", "Settings"))
        .confirmationDialog(L10n.t("Удалить аккаунт навсегда?", "Delete the account forever?"),
                            isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete"), role: .destructive) { deleteAccount() }
        }
        .alert(L10n.t("Аккаунт удалён", "Account deleted"), isPresented: Binding(
            get: { deletion != nil }, set: { if !$0 { finishDeletion() } }
        )) {
            Button("OK") { finishDeletion() }
        } message: {
            // 🔐 Числа, а не просто «готово»: проверить потом уже нечем.
            if let deletion {
                Text(L10n.t("Устройств: \(deletion.devices), недоставленных сообщений: \(deletion.envelopes), вложений: \(deletion.attachments).",
                            "Devices: \(deletion.devices), undelivered messages: \(deletion.envelopes), attachments: \(deletion.attachments)."))
            }
        }
        .task { await load() }
    }

    private func link(_ title: String, _ path: String) -> some View {
        Link(title, destination: AppConfig.docsURL.appendingPathComponent(path))
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let state = try? await Background.run { () -> (String?, FfiProxy) in
            (try messenger.ownUsername(), try messenger.proxy())
        }
        username = state?.0 ?? ""
        viaTor = state?.1 == .tor
        updateTorStatus()
    }

    private func setTor(_ enabled: Bool) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            let mode: FfiProxy = enabled ? .tor : .direct
            _ = try? await Background.run { try messenger.setProxy(proxy: mode) }
            let bridges = try? await Background.run { try messenger.torBridges() }
            NetworkController.shared.apply(proxy: mode, bridges: bridges)
            updateTorStatus()
        }
    }

    private func updateTorStatus() {
        let status = NetworkController.shared.torStatus
        torStatus = status.ready
            ? L10n.t("Tor подключён", "Tor connected")
            : L10n.t("Tor подключается… \(status.percent)%", "Tor connecting… \(status.percent)%")
    }

    private func deleteAccount() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        deleting = true
        error = nil
        Task {
            do {
                deletion = try await Background.run { try messenger.deleteAccount(nowMillis: CoreStore.nowMillis) }
            } catch {
                self.error = L10n.t("Нет связи с сервером — аккаунт не удалён.", "No connection — the account was not deleted.")
            }
            deleting = false
        }
    }

    /// 🔐 После удаления на сервере — всё локальное: база, ключ Enclave.
    private func finishDeletion() {
        deletion = nil
        model.didWipe()
    }
}

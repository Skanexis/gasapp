// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Онбординг: регистрация первого аккаунта.
///
/// 🔐 Предупреждение об отсутствии аудита показывается **до** кнопки
/// и тем же кеглем, что и остальной текст (раздел 21 плана).
/// Мессенджер, обещающий защиту, которую не проверял никто
/// посторонний, обязан сказать об этом до того, как пользователь
/// начнёт ему доверять, — а не в сноске, которую никто не читает.
struct OnboardingView: View {

    // MARK: - Properties

    @State private var username = ""
    @State private var pin = ""
    @State private var errorText: String?
    @State private var isWorking = false

    let onRegister: (String, String) -> Void

    // MARK: - Body

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                Spacer(minLength: 32)

                shield

                Text("GasApp")
                    .font(.system(size: 22, weight: .bold))
                    .foregroundColor(GasAppColor.textPrimary)
                    .padding(.top, 20)

                Text("Мессенджер со сквозным шифрованием, устойчивым к квантовому компьютеру")
                    .font(.system(size: 14))
                    .foregroundColor(GasAppColor.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 10)

                auditWarning
                    .padding(.top, 26)

                usernameField
                    .padding(.top, 18)

                pinField
                    .padding(.top, 16)

                if let errorText {
                    Text(errorText)
                        .font(.system(size: 12))
                        .foregroundColor(GasAppColor.error)
                        .padding(.top, 8)
                }

                if isWorking {
                    VStack(spacing: 8) {
                        ProgressView()

                        Text("Подбирается доказательство работы…")
                            .font(.system(size: 12))
                            .foregroundColor(GasAppColor.textTertiary)
                    }
                    .padding(.top, 14)
                }

                Spacer(minLength: 32)

                GasAppButton(title: "Создать аккаунт", action: register)
                    .padding(.top, 22)
            }
            .padding(24)
        }
        .background(GasAppColor.bgBase.ignoresSafeArea())
    }

    // MARK: - Subviews

    private var shield: some View {
        Image(systemName: "shield.fill")
            .font(.system(size: 32))
            .foregroundColor(GasAppColor.accent)
            .frame(width: 72, height: 72)
            .background(GasAppColor.accentDim)
            .clipShape(RoundedRectangle(cornerRadius: 20))
    }

    /// 🔐 Предупреждение об аудите: красная рамка и полный кегль.
    private var auditWarning: some View {
        Text("Не прошёл независимый аудит. Не используйте для защиты жизни и свободы.")
            .font(.system(size: 14))
            .foregroundColor(GasAppColor.error)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background(GasAppColor.errorDim)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(GasAppColor.error, lineWidth: 1)
            )
    }

    private var usernameField: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Выберите имя пользователя — по нему вас найдут собеседники")
                .font(.system(size: 13))
                .foregroundColor(GasAppColor.textSecondary)

            TextField("имя_пользователя", text: $username)
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .padding(12)
                .background(GasAppColor.bgCard)
                .foregroundColor(GasAppColor.textPrimary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    private var pinField: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Придумайте PIN — им шифруется переписка на устройстве")
                .font(.system(size: 13))
                .foregroundColor(GasAppColor.textSecondary)

            // 🔐 PIN шифрует хранилище: он растягивается Argon2id
            // и даёт ключ базы. Отдельного «пароля от аккаунта» нет
            // и не будет — пароль, который проверяет сервер, ничего
            // не защищал бы на изъятом устройстве.
            SecureField("не менее 6 цифр", text: $pin)
                .textFieldStyle(.plain)
                .padding(12)
                .background(GasAppColor.bgCard)
                .foregroundColor(GasAppColor.textPrimary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    // MARK: - Actions

    private func register() {
        let name = username.trimmingCharacters(in: .whitespacesAndNewlines)

        guard name.count >= Self.minUsernameLength else {
            errorText = "Имя слишком короткое"

            return
        }

        guard pin.count >= Self.minPinLength else {
            errorText = "PIN должен быть не короче 6 символов"

            return
        }

        errorText = nil
        isWorking = true

        onRegister(name, pin)
    }

    // MARK: - Constants

    /// Минимальная длина имени.
    ///
    /// Короткие имена вычерпываются перебором, и злоумышленник занял бы
    /// их все до появления настоящих пользователей.
    private static let minUsernameLength = 3

    /// Минимальная длина PIN — совпадает с проверкой в ядре.
    private static let minPinLength = 6
}

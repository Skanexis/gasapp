import SwiftUI

/**
 * AEGIS Button component with 7 states:
 * 1. Normal
 * 2. Pressed
 * 3. Hovered (not typically used on mobile, but kept for completeness)
 * 4. Focused
 * 5. Disabled
 * 6. Loading
 * 7. Error
 */
struct AegisButton: View {
    // MARK: - Properties

    let title: String
    let action: () -> Void
    var isLoading: Bool = false
    var isError: Bool = false
    var errorMessage: String? = nil
    var showsLoadingIndicator: Bool = true

    // MARK: - Body

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if isLoading && showsLoadingIndicator {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(0.8)
                }

                Text(buttonTitle)
                    .fontWeight(.semibold)
            }
            .frame(minWidth: 0, maxWidth: .infinity)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(AegisButtonStyle(
            isLoading: isLoading,
            isError: isError,
            isDisabled: !isEnabled
        ))
        .disabled(isLoading || !isEnabled) // Disable during loading or when explicitly disabled
    }

    // MARK: - Computed Properties

    private var buttonTitle: String {
        if isLoading {
            return NSLocalizedString("button_loading", comment: "Loading button title")
        } else if isError {
            return errorMessage ?? NSLocalizedString("button_error", comment: "Error button title")
        } else {
            return title
        }
    }

    private var isEnabled: Bool {
        return !isLoading && !isError // In a real app, this would come from view model
    }
}

// MARK: - Button Style

struct AegisButtonStyle: ButtonStyle {
    let isLoading: Bool
    let isError: Bool
    let isDisabled: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(buttonTextColor(for: configuration))
            .background(buttonBackgroundColor(for: configuration))
            .cornerRadius(8)
            .scaleEffect(configuration.isPressed && !isLoading && !isDisabled ? 0.95 : 1.0)
            .opacity(isDisabled ? 0.5 : 1.0)
            .animation(.easeInOut(duration: 0.2), value: configuration.isPressed)
    }

    private func buttonTextColor(for configuration: Configuration) -> Color {
        if isDisabled {
            return .secondary
        } else if isLoading || isError {
            return .white
        } else {
            return configuration.isPressed ? .white : .primary
        }
    }

    private func buttonBackgroundColor(for configuration: Configuration) -> Color {
        if isDisabled {
            return Color(.systemGray4)
        } else if isLoading {
            return .blue
        } else if isError {
            return .red
        } else {
            return configuration.isPressed ? Color(.systemGray2) : Color(.systemBackground)
        }
    }
}

// MARK: - Preview

struct AegisButton_Previews: PreviewProvider {
    static var previews: some View {
        VStack(spacing: 16) {
            AegisButton(title: "Normal Button") {
                print("Button tapped")
            }

            AegisButton(title: "Disabled Button", isLoading: false, isError: false) {
                print("Button tapped")
            }
            .disabled(true)

            AegisButton(title: "Loading Button", isLoading: true) {
                print("Button tapped")
            }

            AegisButton(title: "Error Button", isLoading: false, isError: true, errorMessage: "Try again") {
                print("Button tapped")
            }
        }
        .padding()
        .previewLayout(.sizeThatFits)
    }
}
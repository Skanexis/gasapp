import SwiftUI

/**
 * AEGIS TextField component with visual states:
 * 1. Normal
 * 2. Focused
 * 3. Disabled
 * 4. Error
 */
struct AegisTextField: View {
    // MARK: - Properties

    let placeholder: String
    @Binding var text: String
    var isSecure: Bool = false
    var keyboardType: UIKeyboardType = .default
    var isDisabled: Bool = false
    var errorMessage: String? = nil
    var onEditingChanged: (Bool) -> Void = { _ in }
    var onCommit: () -> Void = {}

    // MARK: - State

    @FocusState private var isFocused: Bool

    // MARK: - Body

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Text field
            Group {
                if isSecure {
                    SecureField(placeholder, text: $text)
                        .disableAutocorrection(true)
                        .textInputAutocapitalization(.never)
                } else {
                    TextField(placeholder, text: $text)
                        .disableAutocorrection(true)
                        .textInputAutocapitalization(.sentences)
                        .keyboardType(keyboardType)
                }
            }
            .padding(12)
            .background(textFieldBackground)
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(borderColor, lineWidth: borderWidth)
            )
            .focused($isFocused)
            .disabled(isDisabled)
            .onChange(of: isFocused) { newValue in
                onEditingChanged(newValue)
            }
            .onSubmit {
                onCommit()
            }

            // Error message
            if let errorMessage = errorMessage, !errorMessage.isEmpty {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.leading, 4)
            }
        }
    }

    // MARK: - Computed Properties

    private var textFieldBackground: Color {
        if isDisabled {
            return Color(.systemGray5)
        } else if isFocused {
            return Color(.systemBackground)
        } else if let _ = errorMessage {
            return Color(.systemGray5)
        } else {
            return Color(.systemBackground)
        }
    }

    private var borderColor: Color {
        if isDisabled {
            return Color(.systemGray3)
        } else if isFocused {
            return .blue
        } else if let _ = errorMessage {
            return .red
        } else {
            return Color(.systemGray4)
        }
    }

    private var borderWidth: CGFloat {
        if isDisabled || isFocused || errorMessage != nil {
            return 1.5
        } else {
            return 1.0
        }
    }
}

// MARK: - Preview

struct AegisTextField_Previews: PreviewProvider {
    static var previews: some View {
        VStack(spacing: 16) {
            AegisTextField(placeholder: "Enter text", text: .constant(""))
                .padding()

            AegisTextField(placeholder: "Secure text", text: .constant(""), isSecure: true)
                .padding()

            AegisTextField(placeholder: "Disabled field", text: .constant("Disabled"), isDisabled: true)
                .padding()

            AegisTextField(
                placeholder: "Field with error",
                text: .constant(""),
                errorMessage: "This field is required"
            )
            .padding()

            AegisTextField(placeholder: "Email field", text: .constant(""), keyboardType: .emailAddress)
                .padding()
        }
        .padding()
        .previewLayout(.sizeThatFits)
    }
}
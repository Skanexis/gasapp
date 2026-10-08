import SwiftUI

/**
 * GasApp ListRow component - a reusable row item for lists
 * Can contain text, icons, and secondary information
 */
struct GasAppListRow: View {
    // MARK: - Properties

    let title: String
    let subtitle: String?
    let icon: String? // SF Symbol name or custom image name
    var isSelected: Bool = false
    var isActivated: Bool = false
    var action: (() -> Void)? = nil
    var showsDisclosureIndicator: Bool = false

    // MARK: - Body

    var body: some View {
        VStack {
            HStack(alignment: .top, spacing: 12) {
                // Icon
                if let iconName = icon {
                    Image(systemName: iconName)
                        .font(.system(size: 24))
                        .frame(width: 28, height: 28)
                        .foregroundColor(.secondary)
                }

                // Text content
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.headline)
                        .foregroundColor(.primary)

                    if let subtitle = subtitle, !subtitle.isEmpty {
                        Text(subtitle)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                // Disclosure indicator
                if showsDisclosureIndicator {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 14))
                        .foregroundColor(.secondary)
                        .opacity(isSelected ? 0.7 : 0.5)
                }
            }
            .padding(.vertical, 8)
            .padding(.horizontal, 16)
            .contentShape(Rectangle())
            .onTapGesture {
                action?()
            }
        }
        .background(listRowBackground)
    }

    // MARK: - Computed Properties

    private var listRowBackground: Color {
        if isActivated {
            return Color(.systemGray4)
        } else if isSelected {
            return Color(.systemGray5)
        } else {
            return Color(.systemBackground)
        }
    }
}

// MARK: - Preview

struct GasAppListRow_Previews: PreviewProvider {
    static var previews: some View {
        List {
            GasAppListRow(
                title: "Normal Row",
                subtitle: "Subtitle text",
                icon: "person.fill"
            )

            GasAppListRow(
                title: "Selected Row",
                subtitle: "This row is selected",
                icon: "star.fill",
                isSelected: true
            )

            GasAppListRow(
                title: "Activated Row",
                subtitle: "This row is activated",
                icon: "checkmark.seal.fill",
                isActivated: true
            )

            GasAppListRow(
                title: "Row with Action",
                subtitle: "Tap to perform action",
                icon: "bolt.fill",
                showsDisclosureIndicator: true
            ) {
                print("Row tapped")
            }

            GasAppListRow(
                title: "Simple Row",
                subtitle: nil,
                icon: nil
            )
        }
        .listStyle(.plain)
        .previewLayout(.sizeThatFits)
        .padding()
    }
}
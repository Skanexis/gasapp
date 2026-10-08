import SwiftUI
import XCTest
import SnapshotTesting

/**
 * Snapshot tests for GasAppTextField component.
 * These tests verify the visual appearance of the text field in different states.
 */
class GasAppTextFieldSnapshotTests: XCTestCase {

    func testGasAppTextFieldNormalState() {
        let textField = GasAppTextField(
            placeholder: "Enter text",
            text: .constant("")
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppTextFieldFocusedState() {
        let textField = GasAppTextField(
            placeholder: "Focused Field",
            text: .constant("")
        )
        .frame(width: 300, height: 50)
        .padding()
        .focused(true) // Simulate focus

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppTextFieldErrorState() {
        let textField = GasAppTextField(
            placeholder: "Error Field",
            text: .constant(""),
            errorMessage: "Invalid input"
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppTextFieldDisabledState() {
        let textField = GasAppTextField(
            placeholder: "Disabled Field",
            text: .constant("Disabled"),
            isDisabled: true
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppTextFieldSecureState() {
        let textField = GasAppTextField(
            placeholder: "Password",
            text: .constant(""),
            isSecure: true
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppTextFieldWithText() {
        let textField = GasAppTextField(
            placeholder: "Enter text",
            text: .constant("Hello, World!")
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }
}
import SwiftUI
import XCTest
import SnapshotTesting

/**
 * Snapshot tests for AegisTextField component.
 * These tests verify the visual appearance of the text field in different states.
 */
class AegisTextFieldSnapshotTests: XCTestCase {

    func testAegisTextFieldNormalState() {
        let textField = AegisTextField(
            placeholder: "Enter text",
            text: .constant("")
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisTextFieldFocusedState() {
        let textField = AegisTextField(
            placeholder: "Focused Field",
            text: .constant("")
        )
        .frame(width: 300, height: 50)
        .padding()
        .focused(true) // Simulate focus

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisTextFieldErrorState() {
        let textField = AegisTextField(
            placeholder: "Error Field",
            text: .constant(""),
            errorMessage: "Invalid input"
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisTextFieldDisabledState() {
        let textField = AegisTextField(
            placeholder: "Disabled Field",
            text: .constant("Disabled"),
            isDisabled: true
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisTextFieldSecureState() {
        let textField = AegisTextField(
            placeholder: "Password",
            text: .constant(""),
            isSecure: true
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisTextFieldWithText() {
        let textField = AegisTextField(
            placeholder: "Enter text",
            text: .constant("Hello, World!")
        )
        .frame(width: 300, height: 50)
        .padding()

        assertSnapshot(matching: textField, as: .image(layout: .device(config: .iPhone13)))
    }
}
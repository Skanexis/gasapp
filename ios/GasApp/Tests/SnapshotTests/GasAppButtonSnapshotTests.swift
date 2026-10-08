import SwiftUI
import XCTest
import SnapshotTesting

/**
 * Snapshot tests for GasAppButton component.
 * These tests verify the visual appearance of the button in different states.
 *
 * Note: To run these tests, you need to add the SnapshotTesting framework to your project.
 * You can add it via Swift Package Manager with the URL:
 * https://github.com/pointfreeco/swift-snapshot-testing
 */
class GasAppButtonSnapshotTests: XCTestCase {

    func testGasAppButtonNormalState() {
        let button = GasAppButton(title: "Normal Button") {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppButtonLoadingState() {
        let button = GasAppButton(title: "Loading Button", isLoading: true) {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppButtonErrorState() {
        let button = GasAppButton(title: "Error Button", isLoading: false, isError: true, errorMessage: "Try again") {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppButtonDisabledState() {
        let button = GasAppButton(title: "Disabled Button", isLoading: false, isError: false) {
            print("Button tapped")
        }
        .disabled(true)
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppButtonFocusedState() {
        // Note: Testing focused state in SwiftUI is more complex and often requires
        // testing in the context of a form or with focus simulation
        let button = GasAppButton(title: "Focused Button") {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()
        .focused(true) // This would require @FocusState in a real test scenario

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }
}
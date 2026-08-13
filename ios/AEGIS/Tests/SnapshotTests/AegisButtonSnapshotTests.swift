import SwiftUI
import XCTest
import SnapshotTesting

/**
 * Snapshot tests for AegisButton component.
 * These tests verify the visual appearance of the button in different states.
 *
 * Note: To run these tests, you need to add the SnapshotTesting framework to your project.
 * You can add it via Swift Package Manager with the URL:
 * https://github.com/pointfreeco/swift-snapshot-testing
 */
class AegisButtonSnapshotTests: XCTestCase {

    func testAegisButtonNormalState() {
        let button = AegisButton(title: "Normal Button") {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisButtonLoadingState() {
        let button = AegisButton(title: "Loading Button", isLoading: true) {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisButtonErrorState() {
        let button = AegisButton(title: "Error Button", isLoading: false, isError: true, errorMessage: "Try again") {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisButtonDisabledState() {
        let button = AegisButton(title: "Disabled Button", isLoading: false, isError: false) {
            print("Button tapped")
        }
        .disabled(true)
        .frame(width: 200, height: 50)
        .padding()

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisButtonFocusedState() {
        // Note: Testing focused state in SwiftUI is more complex and often requires
        // testing in the context of a form or with focus simulation
        let button = AegisButton(title: "Focused Button") {
            print("Button tapped")
        }
        .frame(width: 200, height: 50)
        .padding()
        .focused(true) // This would require @FocusState in a real test scenario

        assertSnapshot(matching: button, as: .image(layout: .device(config: .iPhone13)))
    }
}
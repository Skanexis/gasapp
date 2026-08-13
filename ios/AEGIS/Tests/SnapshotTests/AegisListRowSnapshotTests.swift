import SwiftUI
import XCTest
import SnapshotTesting

/**
 * Snapshot tests for AegisListRow component.
 * These tests verify the visual appearance of the list row in different states.
 */
class AegisListRowSnapshotTests: XCTestCase {

    func testAegisListRowNormalState() {
        let listRow = AegisListRow(
            title: "Normal Row",
            subtitle: "Subtitle text",
            icon: "person.fill"
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisListRowSelectedState() {
        let listRow = AegisListRow(
            title: "Selected Row",
            subtitle: "This row is selected",
            icon: "star.fill",
            isSelected: true
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisListRowActivatedState() {
        let listRow = AegisListRow(
            title: "Activated Row",
            subtitle: "This row is activated",
            icon: "checkmark.seal.fill",
            isActivated: true
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisListRowWithAction() {
        let listRow = AegisListRow(
            title: "Row with Action",
            subtitle: "Tap to perform action",
            icon: "bolt.fill",
            showsDisclosureIndicator: true
        ) {
            print("Row tapped")
        }
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisListRowSimple() {
        let listRow = AegisListRow(
            title: "Simple Row",
            subtitle: nil,
            icon: nil
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testAegisListRowLongText() {
        let listRow = AegisListRow(
            title: "This is a very long title that might wrap onto multiple lines",
            subtitle: "This is also a long subtitle that might wrap",
            icon: "text.alignleft"
        )
        .frame(width: 350, height: 80)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }
}
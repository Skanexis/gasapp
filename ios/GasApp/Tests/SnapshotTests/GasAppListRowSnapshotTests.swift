import SwiftUI
import XCTest
import SnapshotTesting

/**
 * Snapshot tests for GasAppListRow component.
 * These tests verify the visual appearance of the list row in different states.
 */
class GasAppListRowSnapshotTests: XCTestCase {

    func testGasAppListRowNormalState() {
        let listRow = GasAppListRow(
            title: "Normal Row",
            subtitle: "Subtitle text",
            icon: "person.fill"
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppListRowSelectedState() {
        let listRow = GasAppListRow(
            title: "Selected Row",
            subtitle: "This row is selected",
            icon: "star.fill",
            isSelected: true
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppListRowActivatedState() {
        let listRow = GasAppListRow(
            title: "Activated Row",
            subtitle: "This row is activated",
            icon: "checkmark.seal.fill",
            isActivated: true
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppListRowWithAction() {
        let listRow = GasAppListRow(
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

    func testGasAppListRowSimple() {
        let listRow = GasAppListRow(
            title: "Simple Row",
            subtitle: nil,
            icon: nil
        )
        .frame(width: 350, height: 60)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }

    func testGasAppListRowLongText() {
        let listRow = GasAppListRow(
            title: "This is a very long title that might wrap onto multiple lines",
            subtitle: "This is also a long subtitle that might wrap",
            icon: "text.alignleft"
        )
        .frame(width: 350, height: 80)
        .padding()

        assertSnapshot(matching: listRow, as: .image(layout: .device(config: .iPhone13)))
    }
}
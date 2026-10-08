import XCTest

/**
 * UI tests for FFI integration in the GasApp iOS app.
 * These tests verify that FFI function calls work correctly on iOS simulator/device.
 *
 * Note: To run these tests, you need to open the project in Xcode and use the XCTest framework.
 */
class MainActivityFFITests: XCTestCase {

    let app = XCUIApplication()

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.

        // In UI tests it is usually best to stop immediately when a failure occurs.
        continueAfterFailure = false

        // UI tests must launch the application that they test.
        app.launch()
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testFFIFunctionsReturnExpectedResults() throws {
        // Wait for the app to launch and display the version information
        let coreVersionStaticText = app.staticTexts["Core Version:"]
        let protocolVersionStaticText = app.staticTexts["Protocol Version:"]
        let safetyNumberStaticText = app.staticTexts["Safety Number:"]

        // Wait for elements to exist (with timeout)
        let coreVersionExists = coreVersionStaticText.waitForExistence(timeout: 5)
        let protocolVersionExists = protocolVersionStaticText.waitForExistence(timeout: 5)
        let safetyNumberExists = safetyNumberStaticText.waitForExistence(timeout: 5)

        // Verify that the version texts are displayed
        XCTAssertTrue(coreVersionExists, "Core version text should be visible")
        XCTAssertTrue(protocolVersionExists, "Protocol version text should be visible")
        XCTAssertTrue(safetyNumberExists, "Safety number text should be visible")

        // Verify that we're not seeing error messages
        let errorText = app.staticTexts.containing(NSPredicate(format: "label contains[c] %@", "Error:"))
        XCTAssertEqual(errorText.count, 0, "Error text should not be visible")
    }

    func testAppLaunchesWithoutCrashing() throws {
        // Simple test to verify the app launches and is responsive
        XCTAssertTrue(app.state == .runningForeground, "App should be running in foreground")

        // Check that there's at least some text displayed (indicating the UI loaded)
        let anyText = app.staticTexts.element(boundBy: 0)
        XCTAssertTrue(anyText.exists, "At least one text element should be visible")
    }
}
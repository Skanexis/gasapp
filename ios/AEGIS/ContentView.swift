import SwiftUI
import AegisCore

struct ContentView: View {
    @State private var coreVersion: String = "Loading..."
    @State private var protocolVersion: String = "Loading..."
    @State private var safetyNumber: String = "Loading..."

    var body: some View {
        VStack(spacing: 20) {
            Text("AEGIS FFI Demo")
                .font(.title)

            Group {
                Text("Core Version: \(coreVersion)")
                Text("Protocol Version: \(protocolVersion)")
                Text("Safety Number:")
                Text(safetyNumber)
                    .font(.system(.body, design: .monospaced))
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding()
            .frame(maxWidth: .infinity)
            .border(Color.gray, width: 1)

            Button("Refresh") {
                loadAegisData()
            }
            .buttonStyle(.borderedProminent)
            .padding()
        }
        .padding()
        .onAppear {
            loadAegisData()
        }
    }

    private func loadAegisData() {
        // This would be called on a background thread in a real app
        // For simplicity, we're calling it directly here
        // In production, you'd use DispatchQueue or similar to avoid blocking UI

        do {
            let coreVersionResult = AegisCore.coreVersion()
            let protocolVersionResult = AegisCore.protocolVersion()

            // Create sample fingerprints for safety number demo
            let localFingerprint = [UInt8](repeating: 0x11, count: 30)
            let remoteFingerprint = [UInt8](repeating: 0x22, count: 30)
            let safetyNumberResult = try AegisCore.formatSafetyNumber(local: localFingerprint, remote: remoteFingerprint)

            // Update UI on main thread
            DispatchQueue.main.async {
                self.coreVersion = coreVersionResult
                self.protocolVersion = String(protocolVersionResult)
                self.safetyNumber = safetyNumberResult
            }
        } catch {
            DispatchQueue.main.async {
                self.coreVersion = "Error: \(error.localizedDescription)"
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
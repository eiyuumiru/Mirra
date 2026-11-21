import AppKit
import SwiftUI

struct LogsView: View {
    var hardware: [LogSnapshot.Entry]
    @AppStorage("VerboseLogs") private var verbose = false
    @State private var log = ""
    @State private var paused = false
    @State private var unavailable = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button(paused ? "Resume" : "Pause") { paused.toggle() }
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(log, forType: .string)
                }
                .disabled(log.isEmpty)
                Toggle("Verbose", isOn: $verbose)
                Spacer()
                Button("Open Log Folder") {
                    NSWorkspace.shared.open(Self.directory)
                }
            }

            if log.isEmpty || unavailable {
                Text(unavailable ? "Mirra could not read its logs." : "No log entries yet.")
                    .foregroundStyle(.secondary)
            }
            ScrollView {
                Text(log)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .background(Color(nsColor: .textBackgroundColor))
            .border(Color(nsColor: .separatorColor), width: 1)
        }
        .padding(20)
        .task(id: paused) {
            while !paused && !Task.isCancelled {
                do {
                    let snapshot = try await SupportClient.diagnostics()
                    guard !Task.isCancelled else { return }
                    let summary = hardware.isEmpty ? snapshot.entries :
                        hardware + snapshot.entries.filter { $0.source != "Host hardware" }
                    log = summary.reversed().map { entry in
                        let time = entry.observedAt.map { "\($0) " } ?? ""
                        return "\(time)[\(entry.source)] \(entry.message)"
                    }.joined(separator: "\n")
                    unavailable = false
                } catch {
                    guard !Task.isCancelled else { return }
                    unavailable = true
                }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    static let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Mirra/logs", isDirectory: true)
}

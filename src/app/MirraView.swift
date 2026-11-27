import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct MirraView: View {
    @ObservedObject var model: MirraModel
    @AppStorage("MirraAppearance") private var appearance = AppearanceMode.system.rawValue
    @State private var importing = false
    @State private var confirmingReset = false

    private var selection: Binding<Page?> {
        Binding(get: { model.page }, set: { if let page = $0 { model.navigate(to: page) } })
    }

    var body: some View {
        NavigationSplitView {
            List(Page.allCases, selection: selection) { page in
                Label(page.rawValue, systemImage: page.symbol).tag(page)
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 155, ideal: 175)
            .disabled(model.busy)
        } detail: {
            Group {
                switch model.page {
                case .setup: SetupView(model: model) { importing = true }
                case .settings: settings
                case .logs: LogsView(model: model)
                }
            }
            .navigationTitle(model.page.rawValue)
        }
        .frame(minWidth: 650, minHeight: 475)
        .onChange(of: appearance, initial: true) { _, mode in
            NSApp.appearance = AppearanceMode(rawValue: mode)?.appearance
        }
        .alert(model.notice?.title ?? "Mirra", isPresented: Binding(get: { model.notice != nil }, set: {
            if !$0 { model.notice = nil }
        })) {
            Button("OK", role: .cancel) { model.notice = nil }
            Button("Show Logs") {
                model.notice = nil
                model.navigate(to: .logs)
            }
        } message: {
            Text(model.notice?.message ?? "")
        }
        .sheet(isPresented: Binding(get: { model.passwordRequest != nil }, set: {
            if !$0 { model.answerPassword(nil) }
        })) {
            if let request = model.passwordRequest {
                PasswordView(prompt: request.prompt, answer: model.answerPassword)
                    .id(request.id)
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            switch result {
            case .success(let url):
                Task { await model.importProfile(url) }
            case .failure:
                model.notice = Notice(title: "Couldn’t open the saved profile", message: "Choose the ready.json file from your previous setup.")
            }
        }
    }

    private var settings: some View {
        Form {
            Section("Background Support") {
                LabeledContent("Status", value: model.report.title)
                if model.report.actions.contains("start") || model.report.actions.contains("install") {
                    Button(model.report.actions.contains("install") ? "Update Support" : "Start Support") {
                        Task { await model.start() }
                    }
                    .disabled(model.busy)
                }
                if model.report.actions.contains("stop") {
                    Button("Stop Support") { Task { await model.stop() } }
                        .disabled(model.busy)
                }
                if model.report.actions.contains("update_bridge") {
                    Button("Update Bridge") { Task { await model.updateBridge() } }
                        .disabled(model.busy)
                }
                Button("Refresh Status") { Task { await model.refresh() } }
                    .disabled(model.busy || model.checking)
            }

            if model.report.actions.contains("stop") || model.report.actions.contains("start") {
                Section("iPhone Mirroring") {
                    Button("Reset iPhone Mirroring…", role: .destructive) { confirmingReset = true }
                        .disabled(model.busy)
                    Text("Forgets this Mac’s saved pairing instead of restoring it. The next connection pairs again and the iPhone asks for its passcode.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .confirmationDialog("Reset iPhone Mirroring?", isPresented: $confirmingReset) {
                    Button("Reset", role: .destructive) { Task { await model.resetMirroring() } }
                } message: {
                    Text("Support restarts and this Mac pairs with the iPhone again from scratch. Other Macs using the same bridge keep their pairing.")
                }
            }

            Section("Appearance") {
                Picker("Theme", selection: $appearance) {
                    ForEach(AppearanceMode.allCases, id: \.rawValue) { mode in
                        Text(mode.rawValue.capitalized).tag(mode.rawValue)
                    }
                }
                .pickerStyle(.segmented)
            }

            Section("Help") {
                DisclosureGroup("Connection Help") {
                    Text("Keep the bridge iPhone reachable. On the iPhone you want to mirror, enable Wi-Fi and Bluetooth, sign in to the same Apple Account as your Mac, then keep the iPhone locked and nearby.")
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 6)
                }
            }

            if let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
                Section("About") {
                    LabeledContent("Version") { Text(version).textSelection(.enabled) }
                }
            }
        }
        .formStyle(.grouped)
    }
}

private struct PasswordView: View {
    var prompt: String
    var answer: (String?) -> Void
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Authorize Access").font(.headline)
            Text(prompt).foregroundStyle(.secondary)
            SecureField("iPhone account password", text: $password).focused($focused)
            HStack {
                Spacer()
                Button("Cancel") { complete(nil) }.keyboardShortcut(.cancelAction)
                Button("Authorize") { complete(password) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(width: 380)
        .onAppear { focused = true }
    }

    private func complete(_ value: String?) {
        password = ""
        answer(value)
    }
}

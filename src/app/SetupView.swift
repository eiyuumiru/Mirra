import SwiftUI

struct SetupView: View {
    @ObservedObject var model: MirraModel
    var importProfile: () -> Void

    var body: some View {
        Form {
            if let mode = model.mode {
                step(mode)
            } else {
                choices
            }
        }
        .formStyle(.grouped)
        .task { await model.loadSetup() }
    }

    private var choices: some View {
        Group {
            if let action = model.primaryAction {
                Section("Background Support") {
                    LabeledContent {
                        if model.busy || model.pendingConnect || action == .wait {
                            ProgressView().controlSize(.small)
                        } else {
                            Button(action.title) {
                                Task { await model.performPrimaryAction() }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(action == .refresh && model.checking)
                        }
                    } label: {
                        Text(model.report.title)
                        Text(model.report.detail)
                    }
                }
            }
            if let detail = model.report.bridgeUpdateDetail {
                Section("Bridge Update") {
                    LabeledContent {
                        if model.report.actions.contains("update_bridge") {
                            Button("Update Bridge") { Task { await model.updateBridge() } }
                                .disabled(model.busy)
                        }
                    } label: {
                        Text(detail)
                    }
                }
            }
            Section("Bridge iPhone") {
                choice("Connect to an Existing iPhone", symbol: "link",
                       detail: "Pair with an iPhone that already has Mirra Bridge installed.") {
                    model.choose(.existing)
                }
                choice("Set Up a New iPhone", symbol: "iphone",
                       detail: "Install Mirra Bridge on a jailbroken iPhone using SSH.") {
                    model.choose(.new)
                }
            }

            if model.loadingSetup || model.savedSetup != nil || model.setupLoadError != nil {
                Section("Saved Setup") {
                    if model.loadingSetup {
                        ProgressView("Checking for a saved setup…").controlSize(.small)
                    } else if let saved = model.savedSetup {
                        Button("Resume Setup") { model.choose(saved.mode ?? .new, resume: true) }
                    } else if let error = model.setupLoadError {
                        Text(error).foregroundStyle(.secondary)
                        Button("Try Again") { Task { await model.loadSetup() } }
                    }
                }
            }

            Section("Profile") {
                LabeledContent {
                    Button("Import…", action: importProfile)
                        .disabled(model.busy || model.report.actions.contains("stop"))
                } label: {
                    Text("Import a Saved Profile")
                    Text(model.report.actions.contains("stop") ? "Stop background support in Settings before importing." :
                         "Choose a ready.json file from a previous setup.")
                }
            }
        }
    }

    private func choice(_ title: String, symbol: String, detail: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 20)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).fontWeight(.semibold)
                    Text(detail).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(model.busy)
    }

    private func step(_ mode: SetupMode) -> some View {
        let phase = model.setupStatus.phase ?? .new
        let copy = StepCopy(mode: mode, phase: phase)
        return Group {
            Section {
                Text(copy.detail).foregroundStyle(.secondary)
                if phase == .trust, let fingerprint = model.setupStatus.fingerprint {
                    LabeledContent("SSH Fingerprint") {
                        Text(fingerprint).monospaced().textSelection(.enabled)
                    }
                }
            } header: {
                Text(copy.title).accessibilityAddTraits(.isHeader)
            }
            if phase == .new {
                connectionFields(mode)
            }
            HStack {
                Button("Back") { Task { await model.backToSetupChoices() } }
                    .disabled(model.busy)
                Spacer()
                if model.busy {
                    ProgressView().controlSize(.small).accessibilityLabel("Working")
                }
                Button(copy.action) { Task { await model.advanceSetup() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canSubmitSetup)
            }
        }
    }

    private func connectionFields(_ mode: SetupMode) -> some View {
        Section("Connection") {
            Picker("Connect Using", selection: $model.transport) {
                ForEach(Transport.allCases, id: \.self) { transport in
                    Text(transport.title).tag(transport)
                }
            }
            if model.transport == .wifi {
                TextField("Address", text: $model.host, prompt: Text("IP address or hostname"))
            } else {
                Picker("iPhone", selection: $model.selectedDevice) {
                    Text(model.devices.isEmpty ? "No USB iPhones found" : "Select an iPhone").tag(nil as String?)
                    ForEach(model.devices) { device in Text(device.title).tag(device.id as String?) }
                }
                Button(model.scanning ? "Scanning…" : "Refresh USB Devices") { Task { await model.scanUSB() } }
                    .disabled(model.scanning)
            }
            TextField(mode == .existing ? "Bridge Port" : "SSH Port", text: $model.port)
            if mode == .existing {
                SecureField("Pairing Token", text: $model.token, prompt: Text("24 characters"))
            } else {
                TextField("SSH Account", text: $model.account)
            }
        }
        .disabled(model.busy)
        .task(id: model.transport) {
            if model.transport == .usb { await model.scanUSB() }
        }
    }
}

private struct StepCopy {
    var title: String
    var detail: String
    var action: String

    init(mode: SetupMode, phase: SetupPhase) {
        switch phase {
        case .new where mode == .existing:
            title = "Connect to an Existing iPhone"
            detail = "On the bridge iPhone, open Settings → Mirra Bridge and copy the pairing token."
            action = "Pair iPhone"
        case .new:
            title = "Set Up a New iPhone"
            detail = "Use a separate jailbroken iPhone with OpenSSH and ldid installed."
            action = "Continue"
        case .contact:
            title = "Reach Your iPhone"
            detail = "Keep the bridge iPhone connected and confirm that SSH is running."
            action = "Retry Connection"
        case .trust:
            title = "Verify Your iPhone"
            detail = "Compare this fingerprint with the phone’s SSH host key before trusting it."
            action = "Trust iPhone"
        case .authorize:
            title = "Authorize SSH"
            detail = "Mirra will add its public key to the bridge iPhone. Enter the phone’s account password if prompted."
            action = "Authorize SSH"
        case .deploy:
            title = "Install Mirra Bridge"
            detail = "Mirra installs the bridge and prepares its certificate. You may be prompted for the iPhone account password."
            action = "Prepare Connection"
        case .ready, .installed:
            title = "Activate This Bridge"
            detail = "Mirra verified the bridge. Activating it closes any current iPhone Mirroring session and enables background support at login."
            action = "Finish Setup"
        }
    }
}

import AppKit
import SwiftUI

enum Page: String, CaseIterable, Identifiable {
    case setup = "Setup"
    case settings = "Settings"
    case logs = "Logs"

    var id: Self { self }

    var symbol: String {
        switch self {
        case .setup: "plus.circle"
        case .settings: "gearshape"
        case .logs: "list.bullet.rectangle"
        }
    }
}

enum AppearanceMode: String, CaseIterable {
    case system, light, dark

    var appearance: NSAppearance? {
        switch self {
        case .system: nil
        case .light: NSAppearance(named: .aqua)
        case .dark: NSAppearance(named: .darkAqua)
        }
    }
}

enum ConnectionAction: Equatable {
    case connect, update, updateBridge, renew, refresh, wait

    var title: String {
        switch self {
        case .connect: "Connect"
        case .update: "Update and Connect"
        case .updateBridge: "Update Bridge"
        case .renew: "Renew Now"
        case .refresh: "Check Again"
        case .wait: "Connecting…"
        }
    }
}

struct Notice {
    var title: String
    var message: String
}

struct PasswordRequest {
    var prompt: String
    var reply: (String?) -> Void
}

@MainActor
final class MirraModel: ObservableObject {
    @Published var page = Page.setup
    @Published private(set) var report = SupportReport.checking
    @Published private(set) var checking = false
    @Published private(set) var busy = false
    @Published private(set) var pendingConnect = false
    @Published var notice: Notice?
    @Published var passwordRequest: PasswordRequest?
    @Published var hardwareEntries: [LogSnapshot.Entry] = []

    @Published private(set) var mode: SetupMode?
    @Published private(set) var setupStatus = SetupStatus()
    @Published private(set) var savedSetup: SetupStatus?
    @Published private(set) var loadingSetup = false
    @Published private(set) var setupLoadError: String?
    @Published private(set) var devices: [USBDevice] = []
    @Published private(set) var scanning = false
    @Published var transport = Transport.wifi
    @Published var host = ""
    @Published var port = ""
    @Published var account = "mobile"
    @Published var selectedDevice: String?
    @Published var token = ""

    private let client: SupportClient
    private let launchMirroring: () async throws -> Void
    private var revision = 0

    init(client: SupportClient = .live(), launchMirroring: (() async throws -> Void)? = nil) {
        self.client = client
        self.launchMirroring = launchMirroring ?? {
            let url = URL(fileURLWithPath: "/System/Applications/iPhone Mirroring.app", isDirectory: true)
            _ = try await NSWorkspace.shared.openApplication(at: url, configuration: .init())
        }
    }

    var primaryAction: ConnectionAction? {
        if report.state == "setup_required" { return nil }
        if report.actions.contains("install") { return .update }
        if report.actions.contains("open_mirroring") || report.actions.contains("start") { return .connect }
        if report.actions.contains("update_bridge") { return .updateBridge }
        if report.actions.contains("renew") { return .renew }
        return report.isTransitioning ? .wait : .refresh
    }

    func navigate(to destination: Page) {
        guard !busy, page != destination else { return }
        if destination == .setup {
            revision += 1
            pendingConnect = false
        } else if page == .setup {
            revision += 1
            token = ""
        }
        page = destination
    }

    func refresh() async {
        guard !checking, !busy, page != .setup || mode == nil else { return }
        let current = revision
        checking = true
        defer { checking = false }
        do {
            let reply = try await client.control("status", nil)
            guard current == revision, !busy else { return }
            report = reply.report
            await continueConnection()
        } catch {
            guard current == revision, !busy else { return }
            pendingConnect = false
            report = SupportReport(state: "helper_unavailable", title: "Status unavailable",
                                   detail: "Mirra could not read the service status. Try checking again.")
        }
    }

    func performPrimaryAction() async {
        guard !busy, !pendingConnect, let primaryAction else { return }
        switch primaryAction {
        case .connect where report.state == "ready":
            await control("preflight")
        case .connect, .update:
            pendingConnect = true
            await control(primaryAction == .update ? "install" : "start")
        case .renew:
            await control("renew")
        case .updateBridge:
            await updateBridge()
        case .refresh:
            await refresh()
        case .wait:
            break
        }
    }

    func start() async { await control(report.actions.contains("install") ? "install" : "start") }

    func updateBridge() async {
        guard !busy, report.actions.contains("update_bridge") else { return }
        guard let authorization = makeAuthorization() else {
            notice = Notice(title: "Secure password entry is unavailable", message: "Try updating the bridge again.")
            return
        }
        pendingConnect = false
        revision += 1
        busy = true
        defer {
            authorization.invalidate()
            answerPassword(nil)
            busy = false
        }
        do {
            let reply = try await client.setup("update-bridge", SetupRequest(), authorization.environment)
            if let updated = reply.setup.supportReport { report = updated }
            if reply.ok {
                notice = Notice(title: "Bridge Update", message: reply.setup.message ?? report.detail)
            } else {
                notice = Notice(title: "Couldn’t update the bridge",
                                message: reply.setup.error ?? "Check the iPhone connection and try again.")
            }
        } catch {
            notice = Notice(title: "Couldn’t update the bridge", message: "Check the iPhone connection and try again.")
        }
    }

    private func makeAuthorization() -> Authorization? {
        Authorization { [weak self] prompt, reply in
            guard let self else { reply(nil); return }
            self.passwordRequest = PasswordRequest(prompt: prompt, reply: reply)
        }
    }

    func stop() async {
        guard !busy else { return }
        pendingConnect = false
        await control("stop")
    }

    func importProfile(_ url: URL) async { await control("install", profile: url) }

    private func continueConnection() async {
        guard pendingConnect else { return }
        if report.state == "ready" {
            pendingConnect = false
            await control("preflight")
        } else if !report.isTransitioning {
            pendingConnect = false
        }
    }

    private func control(_ action: String, profile: URL? = nil) async {
        guard !busy else { return }
        revision += 1
        busy = true
        do {
            let reply = try await client.control(action, profile)
            report = reply.report
            guard reply.ok else {
                pendingConnect = false
                notice = Notice(title: "Couldn’t complete the action",
                                message: reply.message ?? reply.report.detail)
                busy = false
                return
            }
            if action == "renew" {
                notice = Notice(title: "Bridge Certificate", message: reply.message ?? reply.report.detail)
            }
            if action == "preflight" {
                if reply.preflight?.state == "ready" && report.state == "ready" {
                    do { try await launchMirroring() }
                    catch {
                        notice = Notice(title: "Couldn’t open iPhone Mirroring",
                                        message: "Check that iPhone Mirroring is available in System Applications.")
                    }
                } else {
                    notice = Notice(title: reply.preflight?.title ?? reply.report.title,
                                    message: reply.preflight?.message ?? reply.report.detail)
                }
            }
        } catch {
            pendingConnect = false
            notice = Notice(title: "Mirra’s helper could not finish", message: "Refresh the connection status and try again.")
        }
        busy = false
        await continueConnection()
    }

    func loadSetup() async {
        guard !loadingSetup, !busy, mode == nil else { return }
        loadingSetup = true
        setupLoadError = nil
        let current = revision
        defer { loadingSetup = false }
        do {
            let reply = try await client.setup("status", SetupRequest(), nil)
            guard current == revision else { return }
            if let error = reply.setup.error, !reply.ok {
                setupLoadError = error
                return
            }
            let status = reply.setup
            if status.id != nil, status.phase != .installed {
                savedSetup = status
            } else {
                savedSetup = nil
            }
        } catch {
            guard current == revision else { return }
            setupLoadError = "Mirra could not read the saved setup."
        }
    }

    func choose(_ selection: SetupMode, resume: Bool = false) {
        guard !busy else { return }
        revision += 1
        pendingConnect = false
        mode = selection
        setupStatus = resume ? savedSetup ?? SetupStatus() : SetupStatus()
        transport = .wifi
        host = ""
        port = selection == .existing ? "47820" : "22"
        account = "mobile"
        devices = []
        selectedDevice = nil
        token = ""
    }

    func backToSetupChoices() async {
        guard !busy else { return }
        revision += 1
        mode = nil
        token = ""
        setupStatus = SetupStatus()
        await loadSetup()
    }

    func scanUSB() async {
        guard !busy, !scanning, transport == .usb else { return }
        let current = revision
        scanning = true
        defer { scanning = false }
        do {
            let reply = try await client.setup("devices", SetupRequest(), nil)
            guard current == revision, transport == .usb else { return }
            guard reply.ok else {
                devices = []
                selectedDevice = nil
                notice = Notice(title: "Couldn’t refresh USB devices",
                                message: reply.setup.error ?? "Check the USB cable and try again.")
                return
            }
            devices = reply.setup.devices ?? []
            if !devices.contains(where: { $0.id == selectedDevice }) {
                selectedDevice = devices.count == 1 ? devices.first?.id : nil
            }
        } catch {
            guard current == revision, transport == .usb else { return }
            devices = []
            selectedDevice = nil
            notice = Notice(title: "Couldn’t refresh USB devices", message: "Check the USB cable and try again.")
        }
    }

    var canSubmitSetup: Bool {
        guard !busy, !scanning, let mode else { return false }
        if setupStatus.phase == .trust { return setupStatus.fingerprint?.isEmpty == false }
        if let phase = setupStatus.phase, phase != .new { return true }
        guard let number = Int(port.trimmingCharacters(in: .whitespaces)), (1...65535).contains(number) else { return false }
        if transport == .wifi && host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        if transport == .usb && !devices.contains(where: { $0.id == selectedDevice }) { return false }
        return mode == .existing ? !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                : !account.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func advanceSetup() async {
        guard canSubmitSetup, let mode else { return }
        let phase = setupStatus.phase ?? .new
        var payload = SetupRequest(id: setupStatus.id)
        let action: String
        switch phase {
        case .new:
            let device = devices.first { $0.id == selectedDevice }
            payload = SetupRequest(transport: transport, host: host.trimmingCharacters(in: .whitespacesAndNewlines),
                                   port: port.trimmingCharacters(in: .whitespaces),
                                   user: mode == .new ? account.trimmingCharacters(in: .whitespacesAndNewlines) : nil,
                                   serial: transport == .usb ? device?.id : nil,
                                   productType: transport == .usb ? device?.productType : nil,
                                   token: mode == .existing ? token : nil)
            action = mode == .existing ? "pair" : "begin"
        case .contact: action = "scan"
        case .trust:
            action = "trust"
            payload.fingerprint = setupStatus.fingerprint
        case .authorize: action = "connect"
        case .deploy: action = "provision"
        case .ready: action = "finish"
        case .installed: return
        }

        let authorization: Authorization?
        if phase == .authorize || phase == .deploy {
            authorization = makeAuthorization()
            guard authorization != nil else {
                notice = Notice(title: "Secure password entry is unavailable", message: "Try the setup step again.")
                return
            }
        } else {
            authorization = nil
        }

        busy = true
        revision += 1
        defer {
            authorization?.invalidate()
            answerPassword(nil)
            busy = false
        }
        do {
            let reply = try await client.setup(action, payload, authorization?.environment)
            if !reply.ok && reply.setup.phase == .new && setupStatus.id != nil {
                // A competing process may hold the setup lock. Retain this
                // verified step so the user can retry with the same identifier.
                notice = Notice(title: "Couldn’t finish the setup step", message: reply.setup.error ?? "Try again.")
                return
            }
            setupStatus = reply.setup
            if reply.ok && action == "pair" { token = "" }
            if reply.ok && reply.setup.phase == .installed {
                modeResetAfterInstallation()
            } else if !reply.ok {
                notice = Notice(title: "Couldn’t finish the setup step", message: reply.setup.error ?? "Try again.")
            }
        } catch {
            notice = Notice(title: "Mirra’s setup helper could not finish",
                            message: "Check the phone and try this step again. You can also return to Setup to resume a saved step.")
        }
    }

    private func modeResetAfterInstallation() {
        if let updated = setupStatus.supportReport { report = updated }
        page = .setup
        savedSetup = nil
        mode = nil
        setupStatus = SetupStatus()
    }

    func answerPassword(_ value: String?) {
        let reply = passwordRequest?.reply
        passwordRequest = nil
        reply?(value)
    }
}

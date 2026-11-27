import AppKit
import SwiftUI

@main
struct InterfaceChecks {
    @MainActor
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        Task { @MainActor in
            await run()
            app.stop(nil)
            NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [], timestamp: 0,
                               windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0)
                .map { app.postEvent($0, atStart: true) }
        }
        app.run()
    }

    @MainActor
    static func run() async {
        var count = 0
        func require(_ condition: @autoclosure () -> Bool, _ message: String) {
            count += 1
            guard condition() else {
                FileHandle.standardError.write(Data("\(message)\n".utf8))
                exit(1)
            }
        }

        let setupRequired = SupportReport(state: "setup_required", title: "Set up", detail: "Select a bridge", actions: ["setup"])
        let ready = SupportReport(state: "ready", title: "Bridge is ready", detail: "Ready", actions: ["open_mirroring", "stop"])
        let expired = SupportReport(state: "bridge_certificate_expired", title: "Bridge certificate expired",
                                    detail: "Renew the bridge certificate", actions: ["renew", "refresh", "stop"])
        let outdated = SupportReport(state: "bridge_update_available", title: "Bridge update available",
                                     detail: "Update the iPhone bridge", actions: ["update_bridge", "refresh"])
        var currentReport = setupRequired
        var renewalSucceeded = false
        var commands: [String] = []
        var requests: [SetupRequest] = []
        var preflightReady = false
        var launchCount = 0
        let result = SupportClient(control: { action, _ in
            commands.append(action)
            switch action {
            case "status":
                return ControlReply(ok: true, report: currentReport)
            case "renew":
                return ControlReply(ok: renewalSucceeded, report: renewalSucceeded ? ready : expired,
                                    message: renewalSucceeded ? "A valid bridge certificate is available"
                                                              : "The certificate is still expired")
            case "preflight":
                return ControlReply(ok: true, report: ready, preflight: .init(
                    state: preflightReady ? "ready" : "blocked", title: "Bridge", message: "Check the bridge"))
            default:
                fatalError("Unexpected service action: \(action)")
            }
        }, setup: { action, request, environment in
            commands.append(action)
            requests.append(request)
            switch action {
            case "status": return SetupReply(ok: true, setup: SetupStatus(phase: .new))
            case "update-bridge":
                require(environment?["MIRRA_ASKPASS_SOCKET"] != nil, "Bridge update lost the private password channel")
                return SetupReply(ok: true, setup: SetupStatus(supportReport: expired, message: "Bridge updated"))
            case "devices":
                return SetupReply(ok: true, setup: SetupStatus(devices: [USBDevice(serial: "test123",
                    productType: "iPhone10,5", title: "Test iPhone")]))
            case "pair":
                require(environment == nil, "Existing bridge pairing opened the SSH password helper")
                return SetupReply(ok: true, setup: SetupStatus(id: "paired", phase: .ready, mode: .existing))
            case "begin":
                return SetupReply(ok: true, setup: SetupStatus(id: "new", phase: .trust, fingerprint: "SHA256:fixture"))
            case "trust":
                return SetupReply(ok: true, setup: SetupStatus(id: "new", phase: .authorize))
            case "connect":
                require(environment?["MIRRA_ASKPASS_SOCKET"] != nil, "SSH authorization lost the private password channel")
                return SetupReply(ok: true, setup: SetupStatus(id: "new", phase: .deploy))
            case "provision":
                require(environment?["MIRRA_ASKPASS_SOCKET"] != nil, "Provisioning lost the private password channel")
                return SetupReply(ok: true, setup: SetupStatus(id: "new", phase: .ready))
            case "finish":
                return SetupReply(ok: true, setup: SetupStatus(id: request.id, phase: .installed, supportReport: ready))
            default:
                fatalError("Unexpected setup action: \(action)")
            }
        })
        let model = MirraModel(client: result, launchMirroring: { launchCount += 1 })
        await model.refresh()
        require(model.page == .setup, "First launch did not show Setup")
        require(model.mode == nil, "Setup skipped the connection choices")

        let controller = NSHostingController(rootView: MirraView(model: model))
        let window = NSWindow(contentViewController: controller)
        window.setContentSize(NSSize(width: 760, height: 530))
        window.makeKeyAndOrderFront(nil)
        NSApp.activate()
        try? await Task.sleep(for: .milliseconds(250))
        require(window.isVisible, "The native window did not become visible")
        require(controller.view.fittingSize.width >= 650, "The native layout did not reserve room for the sidebar and form")

        model.choose(.existing)
        require(model.port == "47820", "Existing bridges should use the bridge service port")
        require(!model.canSubmitSetup, "Pair accepted a missing token and address")
        model.host = "192.0.2.10"
        model.token = "ABCDEFGHJKMNPQRSTVWXYZ12"
        await model.advanceSetup()
        require(model.setupStatus.phase == .ready, "Pair did not reach the activation step")
        require(model.token.isEmpty, "Successful pairing retained the token in the form")
        require(requests.last?.transport == .wifi && requests.last?.host == "192.0.2.10",
                "Wi-Fi pairing lost its address")
        require(requests.last?.token != nil && requests.last?.user == nil, "Pair submitted the wrong credentials")
        require(!commands.contains("finish"), "Pair activated the bridge before the user's confirmation")
        await model.advanceSetup()
        require(model.page == .setup && model.mode == nil && model.primaryAction == .connect,
                "Activation did not return to Setup with Connect available")
        require(launchCount == 0, "Finishing setup opened iPhone Mirroring")
        require(requests.last?.id == "paired", "Activation lost the verified profile identifier")

        await model.performPrimaryAction()
        require(launchCount == 0 && model.notice != nil, "Preflight failure opened iPhone Mirroring")
        model.notice = nil
        preflightReady = true
        await model.performPrimaryAction()
        require(launchCount == 1, "Successful preflight did not open iPhone Mirroring")

        model.choose(.existing)
        model.transport = .usb
        await model.scanUSB()
        model.token = "ABCDEFGHJKMNPQRSTVWXYZ12"
        await model.advanceSetup()
        require(requests.last?.serial == "test123" && requests.last?.productType == "iPhone10,5",
                "USB pairing lost the selected device")
        await model.backToSetupChoices()

        model.choose(.new)
        require(model.port == "22", "New setup should use the SSH port")
        model.host = "192.0.2.20"
        model.account = "mobile"
        await model.advanceSetup()
        require(model.setupStatus.phase == .trust, "New setup skipped host verification")
        require(requests.last?.user == "mobile" && requests.last?.token == nil, "New setup sent the wrong credentials")
        await model.advanceSetup()
        require(requests.last?.fingerprint == "SHA256:fixture", "New setup did not submit the displayed fingerprint")
        await model.advanceSetup()
        await model.advanceSetup()
        require(model.setupStatus.phase == .ready, "New setup did not reach certificate verification")
        await model.advanceSetup()
        require(model.page == .setup && model.mode == nil && requests.last?.id == "new",
                "New setup did not activate the verified profile")
        require(commands.filter { $0 == "pair" }.count == 2 && commands.filter { $0 == "begin" }.count == 1,
                "The setup choices selected the wrong helper commands")

        currentReport = expired
        await model.refresh()
        require(model.primaryAction == .renew && model.primaryAction?.title == "Renew Now",
                "An expired certificate did not offer immediate renewal")
        await model.performPrimaryAction()
        require(commands.last == "renew" && model.notice?.message == "The certificate is still expired",
                "Renew Now did not surface the issuer failure")
        renewalSucceeded = true
        await model.performPrimaryAction()
        require(model.report == ready && model.notice?.message == "A valid bridge certificate is available",
                "Renew Now did not surface the certificate success")
        require(launchCount == 1, "Renew Now opened iPhone Mirroring")

        currentReport = outdated
        await model.refresh()
        require(model.primaryAction == .updateBridge, "An outdated bridge did not offer Update Bridge")
        await model.performPrimaryAction()
        require(commands.last == "update-bridge" && model.primaryAction == .renew,
                "Bridge update did not return to the certificate state")
        require(model.notice?.message == "Bridge updated" && launchCount == 1,
                "Bridge update did not report its result independently of Mirroring")

        window.orderOut(nil)
        print("{\"passed\":true,\"native_ui_checks\":\(count),\"external_actions_performed\":false}")
    }
}

import AppKit
import SwiftUI

@MainActor
final class MirraApplication: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let model = MirraModel()
    private var window: NSWindow?
    private var poll: Task<Void, Never>?
    private var logProcess: Process?
    private var logInput: FileHandle?
    private var logVerbose = false

    private var defaultsObserver: NSObjectProtocol?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.mainMenu = makeMenu()

        let controller = NSHostingController(rootView: MirraView(model: model))
        let window = NSWindow(contentViewController: controller)
        window.title = "Mirra"
        window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        window.setContentSize(NSSize(width: 760, height: 530))
        window.contentMinSize = NSSize(width: 650, height: 475)
        window.center()
        window.setFrameAutosaveName("MirraWindow")
        window.delegate = self
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate()

        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.startLogCapture() }
        }
        startLogCapture()
        Task {
            if let snapshot = try? await SupportClient.diagnostics(hardware: true) {
                model.hardwareEntries = snapshot.entries
            }
        }
        poll = Task {
            while !Task.isCancelled {
                if NSApp.isActive || model.pendingConnect {
                    await model.refresh()
                }
                try? await Task.sleep(for: .seconds(model.pendingConnect || model.report.isTransitioning ? 2 : 15))
            }
        }
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        guard window != nil else { return }
        Task { await model.refresh() }
    }

    @objc private func startLogCapture() {
        let verbose = UserDefaults.standard.bool(forKey: "VerboseLogs")
        let arguments = verbose ? ["--verbose"] : []
        if logProcess?.isRunning == true && logVerbose == verbose {
            return
        }
        try? logInput?.close()
        logProcess = nil
        logInput = nil
        guard let process = try? SupportClient.process(.main, "logstream", arguments: arguments) else { return }
        let input = Pipe()
        process.standardInput = input
        // The reader also persists its redacted entries for the diagnostics viewer.
        process.standardOutput = FileHandle.nullDevice
        do {
            try process.run()
            logProcess = process
            logInput = input.fileHandleForWriting
            logVerbose = verbose
        } catch {
            try? input.fileHandleForWriting.close()
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if model.busy {
            NSSound.beep()
            return false
        }
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if model.busy {
            NSSound.beep()
            return .terminateCancel
        }
        return .terminateNow
    }

    func applicationWillTerminate(_ notification: Notification) {
        poll?.cancel()
        if let observer = defaultsObserver {
            NotificationCenter.default.removeObserver(observer)
            defaultsObserver = nil
        }
        try? logInput?.close()
    }

    @objc private func showSettings() { model.navigate(to: .settings) }

    private func makeMenu() -> NSMenu {
        let main = NSMenu()
        let mirra = main.addItem(withTitle: "Mirra", action: nil, keyEquivalent: "")
        let appMenu = NSMenu(title: "Mirra")
        mirra.submenu = appMenu
        appMenu.addItem(withTitle: "About Mirra", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Settings…", action: #selector(showSettings), keyEquivalent: ",").target = self
        appMenu.addItem(.separator())
        let services = appMenu.addItem(withTitle: "Services", action: nil, keyEquivalent: "")
        services.submenu = NSMenu(title: "Services")
        NSApp.servicesMenu = services.submenu
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Mirra", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
            .keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Show All", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit Mirra", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        let edit = NSMenu(title: "Edit")
        main.addItem(withTitle: edit.title, action: nil, keyEquivalent: "").submenu = edit
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        let windows = NSMenu(title: "Window")
        main.addItem(withTitle: windows.title, action: nil, keyEquivalent: "").submenu = windows
        windows.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windows.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windows.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        NSApp.windowsMenu = windows
        return main
    }
}

#if !MIRRA_INTERFACE_CHECKS
@main
struct Mirra {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        let app = NSApplication.shared
        let delegate = MirraApplication()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        withExtendedLifetime(delegate) { app.run() }
    }
}
#endif

import Foundation

struct SupportReport: Decodable, Equatable {
    var state: String
    var title: String
    var detail: String
    var actions: [String] = []
    var bridgeTransport: String?
    var bridgeUpdateDetail: String?

    static let checking = Self(state: "checking", title: "Checking Mirra", detail: "Reading the background service status.")

    var isTransitioning: Bool {
        ["checking", "starting", "stopping", "restoring", "recovering",
         "waiting_for_bridge", "waiting_for_mirroring_exit", "renewing_certificate"].contains(state)
    }
}

struct ControlReply: Decodable {
    struct Preflight: Decodable {
        var state: String
        var title: String?
        var message: String?
    }

    var ok: Bool
    var report: SupportReport
    var message: String?
    var preflight: Preflight?
}

enum SetupMode: String, Codable {
    case existing
    case new
}

enum Transport: String, Codable, CaseIterable {
    case wifi = "ssh"
    case usb

    var title: String { self == .usb ? "USB" : "Wi-Fi" }
}

enum SetupPhase: String, Decodable {
    case new, contact, trust, authorize, deploy, ready, installed
}

struct USBDevice: Decodable, Identifiable, Equatable {
    var serial: String
    var productType: String
    var title: String

    var id: String { serial }
}

struct SetupStatus: Decodable {
    struct Defaults: Decodable {
        var transport: Transport
        var user: String
        var port: Int
    }

    var id: String?
    var phase: SetupPhase?
    var mode: SetupMode?
    var defaults: Defaults?
    var fingerprint: String?
    var devices: [USBDevice]?
    var supportReport: SupportReport?
    var error: String?
    var message: String?
}

struct SetupRequest: Encodable {
    var id: String?
    var transport: Transport?
    var host: String?
    var port: String?
    var user: String?
    var fingerprint: String?
    var serial: String?
    var productType: String?
    var token: String?
}

struct SetupReply: Decodable {
    var ok: Bool
    var setup: SetupStatus
}

struct LogSnapshot: Decodable {
    struct Entry: Decodable {
        var source: String
        var message: String
        var observedAt: String?
    }

    var entries: [Entry]
}

struct SupportClient {
    var control: (String, URL?) async throws -> ControlReply
    var setup: (String, SetupRequest, [String: String]?) async throws -> SetupReply

    static func live(bundle: Bundle = .main) -> Self {
        Self(
            control: { action, profile in
                var arguments = [action]
                if let profile { arguments += ["--profile", profile.path] }
                return try await request(bundle, "control", arguments: arguments)
            },
            setup: { action, requestBody, environment in
                guard let executable = bundle.executableURL else { throw CocoaError(.fileNoSuchFile) }
                let askpass = executable.deletingLastPathComponent().appendingPathComponent("password")
                let encoder = JSONEncoder()
                encoder.keyEncodingStrategy = .convertToSnakeCase
                let input = try encoder.encode(requestBody)
                guard input.count <= 16_384 else { throw CocoaError(.fileWriteUnknown) }
                return try await request(bundle, "setup", arguments: [action, "--askpass", askpass.path],
                                         input: input, environment: environment)
            }
        )
    }

    static func diagnostics(hardware: Bool = false) async throws -> LogSnapshot {
        try await request(.main, "diagnostics", arguments: hardware ? ["--hardware"] : [])
    }

    static func process(_ bundle: Bundle, _ command: String, arguments: [String]) throws -> Process {
        guard let resources = bundle.resourceURL else {
            throw CocoaError(.fileNoSuchFile)
        }
        let task = Process()
        task.executableURL = resources.appendingPathComponent("Support/build/mirra-cli")
        task.arguments = [command] + arguments
        task.standardError = FileHandle.nullDevice
        return task
    }

    private static func request<Reply: Decodable>(_ bundle: Bundle, _ command: String, arguments: [String],
                                                   input: Data? = nil, environment: [String: String]? = nil) async throws -> Reply {
        // Setup sends only small JSON requests. Drain stdout before waiting for
        // exit so larger diagnostic replies cannot fill the pipe and block.
        try await Task.detached(priority: .userInitiated) {
            let task = try process(bundle, command, arguments: arguments)
            let output = Pipe()
            let stdin = Pipe()
            task.standardOutput = output
            task.standardInput = stdin
            if let environment {
                task.environment = ProcessInfo.processInfo.environment.merging(environment) { _, selected in selected }
            }
            try task.run()
            defer { task.waitUntilExit() }
            do {
                if let input { try stdin.fileHandleForWriting.write(contentsOf: input) }
            } catch {
                try? stdin.fileHandleForWriting.close()
                throw error
            }
            try stdin.fileHandleForWriting.close()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            return try decoder.decode(Reply.self, from: data)
        }.value
    }
}

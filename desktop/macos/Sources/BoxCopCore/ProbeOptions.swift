import Foundation

public struct ProbeOptions: Sendable {
    public let configuration: EngineConfiguration
    public init(arguments: [String]) throws {
        guard arguments.count % 2 == 0 else { throw EngineFailure.invalidConfiguration }
        var values: [String: String] = [:]
        for index in stride(from: 0, to: arguments.count, by: 2) {
            let key = arguments[index]
            guard ["--executable", "--arguments", "--data-dir"].contains(key), values[key] == nil else { throw EngineFailure.invalidConfiguration }
            values[key] = arguments[index + 1]
        }
        guard let executable = values["--executable"], executable.hasPrefix("/"), !executable.contains("\0"),
              let dataDirectory = values["--data-dir"], dataDirectory.hasPrefix("/"), !dataDirectory.contains("\0") else { throw EngineFailure.invalidConfiguration }
        var args: [String] = []
        if let encoded = values["--arguments"] {
            guard encoded.utf8.count <= 16384, let bytes = encoded.data(using: .utf8), let decoded = try? JSONDecoder().decode([String].self, from: bytes), decoded.count <= 64, decoded.allSatisfy({ !$0.contains("\0") }) else { throw EngineFailure.invalidConfiguration }
            args = decoded
        }
        configuration = EngineConfiguration(executableURL: URL(fileURLWithPath: executable), arguments: args, dataDirectory: URL(fileURLWithPath: dataDirectory))
    }
}

import Foundation

public enum EngineFailure: String, Error, Equatable, Sendable, CustomStringConvertible {
    case invalidRequest, lineTooLarge, internalError, protocolViolation, notReady, launchFailed, disconnected, timedOut, backpressure, cancelled, invalidConfiguration
    public var description: String {
        switch self {
        case .invalidRequest: return "Engine rejected the request."
        case .lineTooLarge: return "Engine protocol frame exceeded the size limit."
        case .internalError: return "Engine could not complete this request."
        case .protocolViolation: return "Engine returned an unsupported response."
        case .notReady: return "Engine is not ready."
        case .launchFailed: return "Engine could not start. Check the app installation and retry."
        case .disconnected: return "Engine connection ended. Retry to start a new session."
        case .timedOut: return "Engine response timed out. Retry to start a new session."
        case .backpressure: return "Engine is busy. Try again."
        case .cancelled: return "Request cancelled."
        case .invalidConfiguration: return "Engine configuration is invalid."
        }
    }
}

public struct JSONLFramer {
    public static let maximumLineBytes = 262144
    private let limit: Int
    private var buffer = Data()
    public init(maximumLineBytes: Int = Self.maximumLineBytes) { limit = maximumLineBytes }
    public mutating func feed(_ chunk: Data) throws -> [Data] {
        var frames: [Data] = []
        for byte in chunk {
            if byte == 10 { frames.append(buffer); buffer = Data() }
            else {
                guard buffer.count < limit - 1 else { buffer = Data(); throw EngineFailure.lineTooLarge }
                buffer.append(byte)
            }
        }
        return frames
    }
    public func finish() throws { if !buffer.isEmpty { throw EngineFailure.protocolViolation } }
}

/// JSONDecoder silently accepts duplicate fields and integer-valued floats.
/// A bounded lexical pass rejects those before Codable sees the document.
struct StrictJSON {
    private let bytes: [UInt8]
    private var index = 0
    init(_ data: Data) throws {
        guard data.count < JSONLFramer.maximumLineBytes, String(data: data, encoding: .utf8) != nil else { throw EngineFailure.protocolViolation }
        bytes = Array(data)
    }
    mutating func validate() throws {
        try value(depth: 0)
        whitespace()
        guard index == bytes.count else { throw EngineFailure.protocolViolation }
    }
    private mutating func whitespace() { while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 } }
    private mutating func consume(_ byte: UInt8) -> Bool {
        whitespace()
        guard index < bytes.count && bytes[index] == byte else { return false }
        index += 1; return true
    }
    private mutating func string() throws -> String {
        whitespace(); let start = index
        guard consume(34) else { throw EngineFailure.protocolViolation }
        while index < bytes.count {
            let byte = bytes[index]; index += 1
            if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index])) }
            if byte == 92 { guard index < bytes.count else { break }; index += 1 }
            else if byte < 32 { throw EngineFailure.protocolViolation }
        }
        throw EngineFailure.protocolViolation
    }
    private mutating func value(depth: Int, integer: Bool = false) throws {
        guard depth < 32 else { throw EngineFailure.protocolViolation }
        whitespace(); guard index < bytes.count else { throw EngineFailure.protocolViolation }
        if bytes[index] == 123 {
            guard !integer else { throw EngineFailure.protocolViolation }
            index += 1; var keys = Set<String>()
            if consume(125) { return }
            repeat {
                let key = try string()
                guard keys.insert(key).inserted, consume(58) else { throw EngineFailure.protocolViolation }
                try value(depth: depth + 1, integer: ["version", "protocol", "limit"].contains(key))
                if consume(125) { return }
                guard consume(44) else { throw EngineFailure.protocolViolation }
            } while true
        }
        if bytes[index] == 91 {
            guard !integer else { throw EngineFailure.protocolViolation }
            index += 1; if consume(93) { return }
            repeat {
                try value(depth: depth + 1)
                if consume(93) { return }
                guard consume(44) else { throw EngineFailure.protocolViolation }
            } while true
        }
        if bytes[index] == 34 {
            guard !integer else { throw EngineFailure.protocolViolation }
            _ = try string(); return
        }
        let start = index
        while index < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[index]) { index += 1 }
        guard index > start else { throw EngineFailure.protocolViolation }
        let token = String(decoding: bytes[start..<index], as: UTF8.self)
        if integer {
            guard token.range(of: #"^-?(0|[1-9][0-9]*)$"#, options: .regularExpression) != nil else { throw EngineFailure.protocolViolation }
        } else if !["true", "false", "null"].contains(token) {
            guard token.range(of: #"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$"#, options: .regularExpression) != nil else { throw EngineFailure.protocolViolation }
        }
    }
}

struct WireKey: CodingKey, Hashable {
    let stringValue: String
    var intValue: Int? { nil }
    init(_ string: String) { stringValue = string }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}
extension Decoder {
    func object(_ keys: Set<String>) throws -> KeyedDecodingContainer<WireKey> {
        let result = try container(keyedBy: WireKey.self)
        guard Set(result.allKeys.map(\.stringValue)) == keys else { throw EngineFailure.protocolViolation }
        return result
    }
}
extension KeyedDecodingContainer where Key == WireKey {
    func field<T: Decodable>(_ name: String, as: T.Type = T.self) throws -> T { try decode(T.self, forKey: WireKey(name)) }
}

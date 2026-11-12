import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum AlertFeedbackCategory: String, Codable, CaseIterable, Sendable, Identifiable {
    case paste, network, screenSharing = "screen_sharing", emailReview = "email_review"
    case codeVerification = "code_verification", codeReview = "pr_review", pdfReview = "pdf_review", software, workflow, agent, system
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .paste: return "Paste protection"
        case .network: return "Outgoing connections"
        case .screenSharing: return "Screen sharing"
        case .emailReview: return "Email review"
        case .codeVerification: return "Code verification"
        case .codeReview: return "PR review"
        case .pdfReview: return "PDF review"
        case .software: return "Software checks"
        case .workflow: return "AI workflow review"
        case .agent: return "Agent actions"
        case .system: return "System protection"
        }
    }
}

public struct ProductBuild: Sendable {
    public let version: String
    public let build: String
    public init?(version: String, build: String) {
        guard Self.validVersion(version), Self.validVersion(build) else { return nil }
        self.version = version; self.build = build
    }
    public static func validVersion(_ value: String) -> Bool {
        value.range(of: "^[0-9]{1,10}(\\.[0-9]{1,10}){0,3}$", options: .regularExpression) != nil
    }
}

public struct AlertFeedbackReport: Encodable, Sendable {
    public static let maximumTextBytes = 4000
    public let schema_version = 1
    public let kind = "alert_feedback"
    public let report_id: UUID
    public let app_version: String
    public let app_build: String
    public let alert_category: AlertFeedbackCategory
    public let text: String
    public static func validText(_ text: String) -> Bool {
        !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && text.utf8.count <= maximumTextBytes &&
        !text.unicodeScalars.contains { ($0.value < 32 && ![9, 10, 13].contains($0.value)) || $0.value == 127 }
    }
    public init?(id: UUID = UUID(), build: ProductBuild, category: AlertFeedbackCategory, text: String) {
        guard Self.validText(text) else { return nil }
        report_id = id; app_version = build.version; app_build = build.build; alert_category = category; self.text = text
    }
}

public enum ProductReportError: Error { case unavailable, rejected, rateLimited }

private final class ReportRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // Consent names BoxCop; never forward a report to another recipient.
    }
}

public struct ProductReportClient: Sendable {
    private struct Receipt: Decodable { let accepted: Bool }
    public static let endpoint = URL(string: "https://getallay.ai/v1/product-reports")!
    private let session: URLSession
    public init(session: URLSession? = nil) {
        if let session { self.session = session; return }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        self.session = URLSession(configuration: configuration)
    }
    public func send<Report: Encodable & Sendable>(_ report: Report) async throws {
        try Task.checkCancellation()
        var request = URLRequest(url: Self.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("BoxCop-Support/1", forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode(report)
        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request, delegate: ReportRedirects()) }
        catch { try Task.checkCancellation(); throw ProductReportError.unavailable }
        try Task.checkCancellation()
        guard let http = response as? HTTPURLResponse else { throw ProductReportError.unavailable }
        if http.statusCode == 429 { throw ProductReportError.rateLimited }
        if [400, 409, 413, 415, 422].contains(http.statusCode) { throw ProductReportError.rejected }
        guard http.statusCode == 202, data.count <= 1024,
              (try? JSONDecoder().decode(Receipt.self, from: data))?.accepted == true else { throw ProductReportError.unavailable }
    }
}

import XCTest
import EndpointSecurity
@testable import BoxCopEndpointSecurity

final class EndpointSecurityTextTests: XCTestCase {
    func testNullEmptySigningMetadataDoesNotCrash() {
        XCTAssertEqual(EndpointSecurityText.decode(es_string_token_t(length: 0, data: nil)), "")
        XCTAssertEqual(EndpointSecurityText.decode(es_string_token_t(length: 10, data: nil)), "")
    }
    func testUsesTokenLengthWithoutRequiringNullTermination() {
        let bytes: [CChar] = [65, 66, 67]
        bytes.withUnsafeBufferPointer { buffer in
            XCTAssertEqual(EndpointSecurityText.decode(es_string_token_t(length: 2, data: buffer.baseAddress)), "AB")
        }
    }
}

import Foundation
import NetworkExtension
import Network
import BoxCopCore

@objc(BoxCopFilterDataProvider)
final class FilterDataProvider: NEFilterDataProvider {
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // The default action explicitly excludes loopback; local proxies must not bypass policy.
        let loopback = [("127.0.0.1", 8), ("::1", 128)].map { host, prefix in
            NEFilterRule(networkRule: NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: host, port: "0"), prefix: prefix, protocol: .any), action: .filterData)
        }
        let settings = NEFilterSettings(rules: loopback, defaultAction: .filterData)
        apply(settings, completionHandler: completionHandler)
    }
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard flow.direction == .outbound else { return .allow() }
        let socket = flow as? NEFilterSocketFlow
        let remote = socket?.remoteEndpoint as? NWHostEndpoint
        let local = socket?.localEndpoint as? NWHostEndpoint
        let destination = NetworkActivityEvent.destination(urlHost: flow.url?.host, remoteHostname: socket?.remoteHostname)
        let threat = threatProtection.match(urlHost: flow.url?.host, remoteHostname: socket?.remoteHostname)
        let event = NetworkActivityEvent(id: flow.identifier,
            remoteAddress: remote.map { String($0.hostname.prefix(512)) }, remotePort: remote.map { String($0.port.prefix(16)) },
            localAddress: local.map { String($0.hostname.prefix(512)) }, localPort: local.map { String($0.port.prefix(16)) },
            hostname: destination.name, hostnameSource: destination.source, url: flow.url.map { String($0.absoluteString.prefix(2048)) },
            transport: socket?.socketProtocol == IPPROTO_TCP ? "tcp" : socket?.socketProtocol == IPPROTO_UDP ? "udp" : "other",
            socketFamily: socket?.socketFamily, socketType: socket?.socketType, socketProtocol: socket?.socketProtocol,
            flowType: socket == nil ? "non_socket" : "socket", threat: threat, bootSessionID: networkBootSessionID)
        activityService?.observe(event, processToken: flow.sourceProcessAuditToken, appToken: flow.sourceAppAuditToken)
        // Match before payload transfer. Logging failures and unknown process identity cannot bypass this verdict.
        return threat == nil ? .allow() : .drop()
    }
}
let networkBootSessionID: String? = {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0, size < 128 else { return nil }
    var bytes = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else { return nil }
    return String(cString: bytes)
}()
var activityService: NetworkActivityService?
let threatProtection = NetworkThreatProtection()
NEProvider.startSystemExtensionMode()
do {
    let service = try NetworkActivityService(); try service.start(); activityService = service
} catch { fputs("BoxCop network activity service unavailable; threat-host blocking remains independent.\n", stderr) }
dispatchMain()

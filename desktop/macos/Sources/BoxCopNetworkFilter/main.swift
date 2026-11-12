import Foundation
import NetworkExtension
import Network
import BoxCopCore

@objc(BoxCopFilterDataProvider)
final class FilterDataProvider: NEFilterDataProvider {
    private let decisions = DispatchQueue(label: "boxcop.network.decisions", attributes: .concurrent)
    private let slots = DispatchSemaphore(value: 32)
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
        if standaloneNetworkMode {
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
            standaloneService?.observe(event, processToken: flow.sourceProcessAuditToken, appToken: flow.sourceAppAuditToken)
            // Match before payload transfer. Logging failures/unknown process identity cannot bypass this verdict.
            return threat == nil ? .allow() : .drop()
        }
        guard let socket = flow as? NEFilterSocketFlow,
              let token = flow.sourceProcessAuditToken, token.count == 32,
              let remote = socket.remoteEndpoint as? NWHostEndpoint else { InterventionSignal.post(.network, uid: nil); return .drop() }
        let words = token.withUnsafeBytes { pointer in (0..<8).map { pointer.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self) } }
        let request = NetworkRequest(uid: words[1], pid: words[5], version: words[7], host: remote.hostname, port: remote.port,
            transport: socket.socketProtocol == IPPROTO_TCP ? "tcp" : (socket.socketProtocol == IPPROTO_UDP ? "udp" : nil))
        guard slots.wait(timeout: .now()) == .success else { InterventionSignal.post(.network, uid: words[1]); return .drop() }
        decisions.async { [weak self] in
            defer { self?.slots.signal() }
            let allowed = NetworkAuthorization.request(request)
            if !allowed { InterventionSignal.post(.network, uid: request.uid) }
            self?.resumeFlow(flow, with: allowed ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
        }
        return .pause()
    }
}
let networkBootSessionID: String? = {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0, size < 128 else { return nil }
    var bytes = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else { return nil }
    return String(cString: bytes)
}()
let standaloneNetworkMode = Bundle.main.object(forInfoDictionaryKey: "BoxCopNetworkMode") as? String == "standalone"
var standaloneService: NetworkActivityService?
let threatProtection = NetworkThreatProtection()
NEProvider.startSystemExtensionMode()
if standaloneNetworkMode {
    do {
        let service = try NetworkActivityService(); try service.start(); standaloneService = service
    } catch { fputs("BoxCop network activity service unavailable; threat-domain policy remains independent.\n", stderr) }
}
dispatchMain()

// swift-tools-version: 5.9
import PackageDescription

var products: [Product] = [
    .library(name: "BoxCopCore", targets: ["BoxCopCore"]),
    .executable(name: "BoxCopProbe", targets: ["BoxCopProbe"])
]
var targets: [Target] = [
    .target(name: "BoxCopCore"),
    .executableTarget(name: "BoxCopProbe", dependencies: ["BoxCopCore"]),
    .testTarget(name: "BoxCopCoreTests", dependencies: ["BoxCopCore"], resources: [.copy("Fixtures")])
]
var dependencies: [Package.Dependency] = []
#if os(macOS)
targets.append(.testTarget(name: "BoxCopEndpointSecurityTests", dependencies: ["BoxCopEndpointSecurity"]))
products.append(.library(name: "BoxCopEndpointSecurity", targets: ["BoxCopEndpointSecurity"]))
targets.append(.target(name: "BoxCopEndpointSecurity", dependencies: ["BoxCopCore"], linkerSettings: [.linkedLibrary("EndpointSecurity")]))
dependencies.append(.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1"))
products.append(.executable(name: "BoxCop", targets: ["BoxCop"]))
targets.append(.executableTarget(name: "BoxCop", dependencies: ["BoxCopCore", .product(name: "Sparkle", package: "Sparkle")], linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]))
targets.append(.testTarget(name: "BoxCopTests", dependencies: ["BoxCop", "BoxCopCore"]))
products.append(.executable(name: "BoxCopNetworkFilter", targets: ["BoxCopNetworkFilter"]))
targets.append(.executableTarget(name: "BoxCopNetworkFilter", dependencies: ["BoxCopCore", "BoxCopEndpointSecurity"], linkerSettings: [.linkedFramework("NetworkExtension")]))
#endif
let package = Package(name: "BoxCop", platforms: [.macOS(.v14)],
                      products: products, dependencies: dependencies, targets: targets, swiftLanguageVersions: [.v5])

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
dependencies.append(.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1"))
products.append(.executable(name: "BoxCop", targets: ["BoxCop"]))
targets.append(.executableTarget(name: "BoxCop", dependencies: ["BoxCopCore", .product(name: "Sparkle", package: "Sparkle")], linkerSettings: [.linkedLibrary("EndpointSecurity"), .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]))
targets.append(.testTarget(name: "BoxCopTests", dependencies: ["BoxCop", "BoxCopCore"]))
products.append(.executable(name: "BoxCopNetworkFilter", targets: ["BoxCopNetworkFilter"]))
targets.append(.executableTarget(name: "BoxCopNetworkFilter", dependencies: ["BoxCopCore"], linkerSettings: [.linkedFramework("NetworkExtension")]))
products.append(.executable(name: "DraftEvidenceReplay", targets: ["DraftEvidenceReplay"]))
targets.append(.executableTarget(name: "DraftEvidenceReplay", dependencies: ["BoxCopCore"]))
#endif
let package = Package(name: "BoxCop", platforms: [.macOS(.v14)],
                      products: products, dependencies: dependencies, targets: targets, swiftLanguageVersions: [.v5])

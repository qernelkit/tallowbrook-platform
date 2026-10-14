// swift-tools-version: 6.0
// Code shared between the iOS app and our server-side Swift (the sync server builds
// SyncProtocol on Linux). Dependencies are pinned exactly; bump them in a PR of their own.
import PackageDescription

let package = Package(
    name: "TallowbrookKit",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "SyncProtocol", targets: ["SyncProtocol"]),
        .library(name: "OfflineCache", targets: ["OfflineCache"]),
        .library(name: "LiveTracking", targets: ["LiveTracking"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", exact: "1.10.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.2"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.103.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.37.5"),
    ],
    targets: [
        .target(
            name: "SyncProtocol",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .target(
            name: "OfflineCache",
            dependencies: [
                .product(name: "CryptoSwift", package: "CryptoSwift")
            ]
        ),
        .target(
            name: "LiveTracking",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        ),
        .testTarget(
            name: "SyncProtocolTests",
            dependencies: ["SyncProtocol"]
        ),
    ]
)

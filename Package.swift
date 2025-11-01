// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Schlussel",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9)
    ],
    products: [
        .library(
            name: "Schlussel",
            targets: ["Schlussel"]
        ),
    ],
    targets: [
        // Binary target for the pre-built XCFramework
        .binaryTarget(
            name: "SchlusselFFI",
            path: "SchlusselFFI.xcframework"
        ),
        // Swift wrapper
        .target(
            name: "Schlussel",
            dependencies: ["SchlusselFFI"],
            path: "Sources/Schlussel"
        ),
        .testTarget(
            name: "SchlusselTests",
            dependencies: ["Schlussel"],
            path: "Tests/SchlusselTests"
        ),
    ]
)

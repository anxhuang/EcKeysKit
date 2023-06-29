// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EcKeysKit",
    products: [
        .library(
            name: "EcKeysKit",
            targets: ["EcKeysKit"]),
    ],
    targets: [
        .target(
            name: "EcKeysKit",
            path: "Sources"),
        .testTarget(
            name: "EcKeysKitTests",
            dependencies: ["EcKeysKit"]),
    ]
)

// swift-tools-version: 5.7
import PackageDescription

let packageName = "SudoKeyManager"
let package = Package(
    name: packageName,
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: packageName,
            targets: [packageName]),
    ],
    dependencies: [
        .package(url: "https://github.com/1024jp/GzipSwift", from: "5.0.0"),
        .package(url: "https://github.com/tikhop/ASN1Swift.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: packageName, dependencies: [
                .product(name: "Gzip", package: "GzipSwift"),
                .product(name: "ASN1Swift", package: "ASN1Swift")
            ],
            path: "SudoKeyManager"
        )
    ]
)

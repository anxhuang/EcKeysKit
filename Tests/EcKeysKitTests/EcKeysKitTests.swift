import XCTest
@testable import EcKeysKit

final class EcKeysKitTests: XCTestCase {
    
    func testP256r1() throws {
        try EcKeysKitTester<P256r1.EcPrivateKey>(sample: .p256r1).assertAll()
    }
    
    func testP384r1() throws {
        try EcKeysKitTester<P384r1.EcPrivateKey>(sample: .p384r1).assertAll()
    }
    
    func testP521r1_64() throws {
        try EcKeysKitTester<P521r1.EcPrivateKey>(sample: .p521r1_64).assertAll()
    }
    
    func testP521r1_65() throws {
        try EcKeysKitTester<P521r1.EcPrivateKey>(sample: .p521r1_65).assertAll()
    }
    
    func testP521r1_66() throws {
        try EcKeysKitTester<P521r1.EcPrivateKey>(sample: .p521r1_66).assertAll()
    }
}



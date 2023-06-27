import CryptoKit
import XCTest

final class CryptoKitTests: XCTestCase {

    func testP256() throws {
        try CryptoKitTester<P256.KeyAgreement.PrivateKey>(sample: .p256r1).assertAll()
    }
    
    func testP384() throws {
        try CryptoKitTester<P384.KeyAgreement.PrivateKey>(sample: .p384r1).assertAll()
    }
    
//    func testP521_64() throws {} // Not supported by CryptoKit
    
//    func testP521_65() throws {} // Not supported by CryptoKit
    
    func testP521_66() throws {
        try CryptoKitTester<P521.KeyAgreement.PrivateKey>(sample: .p521r1_66).assertAll()
    }
}


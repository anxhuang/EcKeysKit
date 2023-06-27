import XCTest
@testable import EcKeysKit

struct EcKeysKitTester<PrivateKey: EcPrivateKeyProtocol> {
    
    let sample: Sample
    
    func assertAll() throws {
        try assertDerKeys()
        try assertX963Keys()
        try assertSharedSecret()
    }

    func assertDerKeys() throws {
        let privateKey = try PrivateKey(der: sample.der.privateKey, pub: sample.der.publicKey)
        let publicKey = try PrivateKey.PublicKey(der: sample.der.publicKey)
        XCTAssertEqual(privateKey.publicKey.raw,
                       publicKey.raw)
    }
    
    func assertX963Keys() throws {
        let privateKey = try PrivateKey(x963: sample.x963.privateKey)
        let publicKey = try PrivateKey.PublicKey(x963: sample.x963.publicKey)
        XCTAssertEqual(privateKey.publicKey.raw,
                       publicKey.raw)
    }
    
    func assertSharedSecret() throws {
        let derPrivateKey = try PrivateKey(der: sample.der.privateKey, pub: sample.der.publicKey)
        let x963PrivateKey = try PrivateKey(x963: sample.x963.privateKey)
        let derSecret = try derPrivateKey.sharedSecret(with: x963PrivateKey.publicKey)
        let x963Secret = try x963PrivateKey.sharedSecret(with: derPrivateKey.publicKey)
        XCTAssertEqual(derSecret, x963Secret)
    }
}

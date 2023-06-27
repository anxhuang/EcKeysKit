import CryptoKit
import XCTest

protocol CryptoKitPublicKey {
    init(derRepresentation: Data) throws
    init(x963Representation: Data) throws
    var rawRepresentation: Data { get }
}

extension P256.KeyAgreement.PublicKey: CryptoKitPublicKey {}
extension P384.KeyAgreement.PublicKey: CryptoKitPublicKey {}
extension P521.KeyAgreement.PublicKey: CryptoKitPublicKey {}

protocol CryptoKitPrivateKey: CryptoKitPublicKey {
    associatedtype PublicKey: CryptoKitPublicKey
    var publicKey: PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKeyShare: PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: CryptoKitPrivateKey {}
extension P384.KeyAgreement.PrivateKey: CryptoKitPrivateKey {}
extension P521.KeyAgreement.PrivateKey: CryptoKitPrivateKey {}

struct CryptoKitTester<PrivateKey: CryptoKitPrivateKey> {
    
    let sample: Sample
    
    func assertAll() throws {
        try assertDerKeys()
        try assertX963Keys()
        try assertSharedSecret()
    }
    
    func assertDerKeys() throws {
        let privateKey = try PrivateKey(derRepresentation: sample.der.privateKey)
        let publicKey = try PrivateKey.PublicKey(derRepresentation: sample.der.publicKey)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation,
                       publicKey.rawRepresentation)
    }
    
    func assertX963Keys() throws {
        let privateKey = try PrivateKey(x963Representation: sample.x963.privateKey)
        let publicKey = try PrivateKey.PublicKey(x963Representation: sample.x963.publicKey)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation,
                       publicKey.rawRepresentation)
    }
    
    func assertSharedSecret() throws {
        let derPrivateKey = try PrivateKey(derRepresentation: sample.der.privateKey)
        let x963PrivateKey = try PrivateKey(x963Representation: sample.x963.privateKey)
        let derSecret = try derPrivateKey.sharedSecretFromKeyAgreement(with: x963PrivateKey.publicKey)
        let x963Secret = try x963PrivateKey.sharedSecretFromKeyAgreement(with: derPrivateKey.publicKey)
        XCTAssertEqual(derSecret, x963Secret)
    }
}

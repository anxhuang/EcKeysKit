//
//  EcKeysKit-Objc.swift
//  EcKeysKit
//
//  Created by user on 2023/6/29.
//

import Foundation

@objc protocol EcKeyObjcProtocol {
    var bytes: Data { get }
    var raw: Data { get }
    var x963: Data { get }
    var der: Data { get }
}

@objc protocol EcPublicKeyObjcProtocol: EcKeyObjcProtocol {
    init(x963: Data) throws
    init(der: Data) throws
}

@objc protocol EcPrivateKeyObjcProtocol: EcKeyObjcProtocol {
    init(random: Bool)
    init(x963: Data) throws
    init(der: Data, pub: Data) throws
    init(derWithPub: Data) throws
}

@objcMembers public class P256r1EcPublicKey: NSObject, EcPublicKeyObjcProtocol {
    
    fileprivate var core: P256r1.EcPublicKey!
    
    public var bytes: Data { core.bytes }
    
    public var raw: Data { core.raw }
    
    public var x963: Data { core.x963 }
    
    public var der: Data { core.der }
    
    public required init(x963: Data) throws {
        core = try .init(x963: x963)
    }
    
    public required init(der: Data) throws {
        core = try .init(der: der)
    }
}

@objcMembers public class P256r1EcPrivateKey: NSObject, EcPrivateKeyObjcProtocol {
    
    private var core: P256r1.EcPrivateKey!
    
    public var bytes: Data { core.bytes }
    
    public var raw: Data { core.raw }
    
    public var x963: Data { core.x963 }
    
    public var der: Data { core.der }
    
    public required init(random: Bool = true) {
        core = .init(random: random)
    }
    
    public required init(x963: Data) throws {
        core = try .init(x963: x963)
    }
    
    public required init(der: Data, pub: Data) throws {
        core = try .init(der: der, pub: pub)
    }
    
    public required init(derWithPub: Data) throws {
        core = try .init(derWithPub: derWithPub)
    }
    
    public func sharedSecret(with publicKey: P256r1EcPublicKey) throws -> Data {
        try core.sharedSecret(with: publicKey.core)
    }
}

@objcMembers public class P384r1EcPublicKey: NSObject, EcPublicKeyObjcProtocol {
    
    fileprivate var core: P384r1.EcPublicKey!
    
    public var bytes: Data { core.bytes }
    
    public var raw: Data { core.raw }
    
    public var x963: Data { core.x963 }
    
    public var der: Data { core.der }
    
    public required init(x963: Data) throws {
        core = try .init(x963: x963)
    }
    
    public required init(der: Data) throws {
        core = try .init(der: der)
    }
}

@objcMembers public class P384r1EcPrivateKey: NSObject, EcPrivateKeyObjcProtocol {
    
    private var core: P384r1.EcPrivateKey!
    
    public var bytes: Data { core.bytes }
    
    public var raw: Data { core.raw }
    
    public var x963: Data { core.x963 }
    
    public var der: Data { core.der }
    
    public required init(random: Bool = true) {
        core = .init(random: random)
    }
    
    public required init(x963: Data) throws {
        core = try .init(x963: x963)
    }
    
    public required init(der: Data, pub: Data) throws {
        core = try .init(der: der, pub: pub)
    }
    
    public required init(derWithPub: Data) throws {
        core = try .init(derWithPub: derWithPub)
    }
    
    public func sharedSecret(with publicKey: P384r1EcPublicKey) throws -> Data {
        try core.sharedSecret(with: publicKey.core)
    }
}

@objcMembers public class P521r1EcPublicKey: NSObject, EcPublicKeyObjcProtocol {
    
    fileprivate var core: P521r1.EcPublicKey!
    
    public var bytes: Data { core.bytes }
    
    public var raw: Data { core.raw }
    
    public var x963: Data { core.x963 }
    
    public var der: Data { core.der }
    
    public required init(x963: Data) throws {
        core = try .init(x963: x963)
    }
    
    public required init(der: Data) throws {
        core = try .init(der: der)
    }
}

@objcMembers public class P521r1EcPrivateKey: NSObject, EcPrivateKeyObjcProtocol {
    
    private var core: P521r1.EcPrivateKey!
    
    public var bytes: Data { core.bytes }
    
    public var raw: Data { core.raw }
    
    public var x963: Data { core.x963 }
    
    public var der: Data { core.der }
    
    public required init(random: Bool = true) {
        core = .init(random: random)
    }
    
    public required init(x963: Data) throws {
        core = try .init(x963: x963)
    }
    
    public required init(der: Data, pub: Data) throws {
        core = try .init(der: der, pub: pub)
    }
    
    public required init(derWithPub: Data) throws {
        core = try .init(derWithPub: derWithPub)
    }
    
    public func sharedSecret(with publicKey: P521r1EcPublicKey) throws -> Data {
        try core.sharedSecret(with: publicKey.core)
    }
}

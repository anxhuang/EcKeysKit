import Foundation

public enum EcKeyError: Error {
    case parseEcPrivateKeyFailed
    case parseEcPublicKeyFailed
}

public protocol EcKeyProtocol {
    static var asn1Prefix: Data { get }
    var secKey: SecKey! { get set }
    var bytes: Data! { get set }
    var raw: Data { get }
    var x963: Data { get }
    var der: Data { get }
}

extension EcKeyProtocol {
    fileprivate func x963SecKey(keyClass: CFString) throws -> SecKey {
        let attr: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: keyClass
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(x963 as CFData, attr as CFDictionary, &error) else {
            throw error!.takeRetainedValue()
        }
        return key
    }
}

public protocol EcPublicKeyProtocol: EcKeyProtocol {
    init()
    init(x963: Data) throws
    init(der: Data) throws
}

public extension EcPublicKeyProtocol {
    var raw: Data { bytes.dropFirst() } // Drop Prefix [0x04]
    var x963: Data { bytes }
    var der: Data { Self.asn1Prefix + bytes }
    
    init(x963: Data) throws {
        self.init()
        bytes = x963
        secKey = try x963SecKey(keyClass: kSecAttrKeyClassPublic)
    }

    init(der: Data) throws {
        self.init()
        bytes = der.dropFirst(Self.asn1Prefix.count)
        secKey = try x963SecKey(keyClass: kSecAttrKeyClassPublic)
    }
}

public protocol EcPrivateKeyProtocol: EcKeyProtocol {
    static var asn1PrefixS1: Data { get }
    static var asn1PrefixS2: Data { get }
    associatedtype PublicKey: EcPublicKeyProtocol
    var publicKey: PublicKey! { get set }

    init(random: Bool)
    init(x963: Data) throws
    init(der: Data, pub: Data) throws
    init(derWithPub: Data) throws
}

public extension EcPrivateKeyProtocol {
    var raw: Data { bytes }
    var x963: Data { publicKey.bytes + bytes }
    var der: Data { Self.asn1Prefix + bytes }
    var derWithPub: Data { Self.asn1PrefixS1 + bytes + Self.asn1PrefixS2 + publicKey.bytes }

    init(x963: Data) throws {
        self.init(random: false)
        if let last = Self.asn1Prefix.last {
            let len = Int(last)
            bytes = x963.suffix(len)
            publicKey = try PublicKey(x963: x963.dropLast(len))
            secKey = try x963SecKey(keyClass: kSecAttrKeyClassPrivate)
        } else {
            throw EcKeyError.parseEcPrivateKeyFailed
        }
    }

    init(der: Data, pub: Data) throws {
        self.init(random: false)
        bytes = try parseBytes(der: der)
        publicKey = try PublicKey(der: pub)
        secKey = try x963SecKey(keyClass: kSecAttrKeyClassPrivate)
    }

    init(derWithPub: Data) throws {
        self.init(random: false)
        bytes = try parseBytes(der: derWithPub)

        if let value = PublicKey.asn1Prefix.dropLast().last,
           case let pubLen = Int(value),
           case let pub = derWithPub.dropFirst(Self.asn1PrefixS1.count + bytes.count).suffix(pubLen),
              pub.count == pubLen {
            publicKey = try PublicKey(x963: pub.dropFirst()) // Drop EOC [0x00]
        } else {
            throw EcKeyError.parseEcPublicKeyFailed
        }
        secKey = try x963SecKey(keyClass: kSecAttrKeyClassPrivate)
    }

    private func parseBytes(der: Data) throws -> Data {
        if let range = der.firstRange(of: [0x02, 0x01, 0x01, 0x04]),
           let keyLen = Self.asn1Prefix.last {
            let lenIdx = range.upperBound
            let len = Int(der[lenIdx])
            let begin = lenIdx + 1
            let end = begin + len
            var data = der[begin..<end]
            while data.count < keyLen {
                data = Data([0x00]) + data
            }
            return data
        } else {
            throw EcKeyError.parseEcPrivateKeyFailed
        }
    }

    fileprivate static func randomSecKey(size: Int) throws -> SecKey {
        let attr: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: size,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attr as CFDictionary, &error) else {
            throw error!.takeRetainedValue()
        }
        return key
    }

    func sharedSecret(with publicKey: EcPublicKeyProtocol) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(secKey, .ecdhKeyExchangeStandard, publicKey.secKey, [:] as CFDictionary, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        return secret
    }
}

/*
 X.509 ASN1 Encoded Keys

 https://stackoverflow.com/a/49627153
 Ref: RFC 5480 - SubjectPublicKeyInfo's ASN encoded header

 https://learn.microsoft.com/zh-tw/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding
 # Basic TLV structure

   ## Short Form(Len < 127)
      - Tag[Len(bytes)]: Value

   ## Long Form(Len >= 127)
      - Tag[Lens(n): Len1, Len2]: Value

      > `Lens(n)`: Presents how much bytes followed as length
      > ex. 0x81 = 10000001 = 1 byte followed

   ## EOC
      - TAG for End-Of-Content

 https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.5
 ansi-X9-62  OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) 10045 }
 id-public-key-type OBJECT IDENTIFIER  ::= { ansi-X9.62 2 }
 id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 }


 https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
 Named Curves:
 */

public enum P256r1 {
    /*
     secp256r1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 }
     */
    public struct EcPublicKey: EcPublicKeyProtocol {
        public var secKey: SecKey!
        public var bytes: Data!
        public static let asn1Prefix = Data([
            0x30, 0x59, // SEQUENCE[89]
            0x30, 0x13, // SEQUENCE[19]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID[8]: 1.2.840.10045.3.1.7
            0x03, 0x42, // BITSTRING[66]
            0x00 // EOC
        ])
        
        public init() {}
    }

    public struct EcPrivateKey: EcPrivateKeyProtocol {
        public var secKey: SecKey!
        public var bytes: Data!
        public var publicKey: P256r1.EcPublicKey!

        public init(random: Bool = true) {
            if random {
                self = try! Self(x963: try! Self.randomSecKey(size: 256).data)
            }
        }
        /* JAVA 8 secp256r1:
         3041 020100 3013 06072A8648CE3D0201 06082A8648CE3D030107 0427 3025 020101 0420 [PRI-32 Bytes]
         */
        public static let asn1Prefix = Data([
            0x30, 0x41, // SEQUENCE[65]
            0x02, 0x01, 0x00, // INTEGER[1]: 0
            0x30, 0x13, // SEQUENCE[19]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID[8]: 1.2.840.10045.3.1.7
            0x04, 0x27, // OCTETSTRING[39]
            0x30, 0x25, // SEQUENCE[37]
            0x02, 0x01, 0x01, // INTEGER[1]: 1
            0x04, 0x20 // OCTETSTRING[32]
        ])
        /* iOS 14 secp256r1:
         308187 020100 3013 06072A8648CE3D0201 06082A8648CE3D030107 046D 306B 020101 0420 [PRI-32 Bytes] A144 0342 00 [PUB-65 Bytes]
         */
        public static let asn1PrefixS1 = Data([
            0x30, 0x81, 0x87, // SEQUENCE[LONG(1): 135]
            0x02, 0x01, 0x00, // INTEGER[1]: 0
            0x30, 0x13, // SEQUENCE[19]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID[5]: 1.3.132.0.35
            0x04, 0x6D, // OCTETSTRING[109]
            0x30, 0x6B, // SEQUENCE[107]
            0x02, 0x01, 0x01, // INTEGER[1]: 1
            0x04, 0x20 // OCTETSTRING[32]
        ])
        public static let asn1PrefixS2 = Data([
            0xA1, 0x44, // CONTEXT SPECIFIC(1)[68]
            0x03, 0x42, // BITSTRING[66]
            0x00 // EOC
        ])
    }
}

public enum P384r1 {
    /*
     secp384r1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) certicom(132) curve(0) 34 }
     */
    public struct EcPublicKey: EcPublicKeyProtocol {
        public var secKey: SecKey!
        public var bytes: Data!
        public static let asn1Prefix = Data([
            0x30, 0x76, // SEQUENCE[118]
            0x30, 0x10, // SEQUENCE[16]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22,  // OID[5]: 1.3.132.0.34
            0x03, 0x62, // BITSTRING[98]
            0x00 // EOC
        ])
        
        public init() {}
    }

    public struct EcPrivateKey: EcPrivateKeyProtocol {
        public var secKey: SecKey!
        public var bytes: Data!
        public var publicKey: P384r1.EcPublicKey!

        public init(random: Bool = true) {
            if random {
                self = try! Self(x963: try! Self.randomSecKey(size: 384).data)
            }
        }
        /* JAVA 8 secp384r1:
         304E 020100 3010 06072A8648CE3D0201 06052B81040022 0437 3035 020101 0430 [PRI-48 Bytes]
         */
        public static let asn1Prefix = Data([
            0x30, 0x4E, // SEQUENCE[78]
            0x02, 0x01, 0x00, // INTEGER[1]: 0
            0x30, 0x10, // SEQUENCE[16]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, // OID[8]: 1.3.132.0.34
            0x04, 0x37, // OCTETSTRING[55]
            0x30, 0x35, // SEQUENCE[53]
            0x02, 0x01, 0x01, // INTEGER[1]: 1
            0x04, 0x30 // OCTETSTRING[48]
        ])
        /* iOS 14 secp384r1:
         3081B6 020100 3010 06072A8648CE3D0201 06052B81040022 04819E 30819B 020101 0430 [PRI-48 Bytes] A1640362 00 [PUB-97 Bytes]
         */
        public static let asn1PrefixS1 = Data([
            0x30, 0x81, 0xB6, // SEQUENCE[LONG(1): 182]
            0x02, 0x01, 0x00, // INTEGER[1]: 0
            0x30, 0x10, // SEQUENCE[16]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, // OID[5]: 1.3.132.0.34
            0x04, 0x81, 0x9E, // OCTETSTRING[LONG(1): 158]
            0x30, 0x81, 0x9B, // SEQUENCE[LONG(1): 155]
            0x02, 0x01, 0x01, // INTEGER[1]: 1
            0x04, 0x30 // OCTETSTRING[48]
        ])
        public static let asn1PrefixS2 = Data([
            0xA1, 0x64, // CONTEXT SPECIFIC(1)[100]
            0x03, 0x62, // BITSTRING[98]
            0x00 // EOC
        ])

    }
}

public enum P521r1 {
    /*
     secp521r1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) certicom(132) curve(0) 35 }
     */
    public struct EcPublicKey: EcPublicKeyProtocol {
        public var secKey: SecKey!
        public var bytes: Data!
        public static let asn1Prefix = Data([
            0x30, 0x81, 0x9B, // SEQUENCE[LONG(1): 155]
            0x30, 0x10, // SEQUENCE[16]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, // OID[5]: 1.3.132.0.35
            0x03, 0x81, 0x86, // BITSTRING[LONG(1): 134]
            0x00 // EOC
        ])
        
        public init() {}
    }

    public struct EcPrivateKey: EcPrivateKeyProtocol {
        public var secKey: SecKey!
        public var bytes: Data!
        public var publicKey: P521r1.EcPublicKey!

        public init(random: Bool = true) {
            if random {
                self = try! Self(x963: try! Self.randomSecKey(size: 521).data)
            }
        }
        /* JAVA 8 secp521r1:
        3060 020100 3010 06072A8648CE3D0201 06052B81040023 0449 3047 020101 0442 [PRI-66 Bytes]
        305F 020100 3010 06072A8648CE3D0201 06052B81040023 0448 3046 020101 0441 [PRI-65 Bytes]
        305E 020100 3010 06072A8648CE3D0201 06052B81040023 0447 3045 020101 0440 [PRI-64 Bytes]
        */
        public static let asn1Prefix = Data([
            0x30, 0x60, // SEQUENCE[96]
            0x02, 0x01, 0x00, // INTEGER[1]: 0
            0x30, 0x10, // SEQUENCE[16]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, // OID[5]: 1.3.132.0.35
            0x04, 0x49, // OCTETSTRING[73]
            0x30, 0x47, // SEQUENCE[71]
            0x02, 0x01, 0x01, // INTEGER[1]: 1
            0x04, 0x42 // OCTETSTRING[66]
        ])
        /* iOS 14 secp521r1:
         3081EE 020100 3010 06072A8648CE3D0201 06052B81040023 0481D6 3081D3 020101 0442 [PRI-66 Bytes] A18189 038186 00 [PUB-133 Bytes]
         */
        public static let asn1PrefixS1 = Data([
            0x30, 0x81, 0xEE, // SEQUENCE[LONG(1): 238]
            0x02, 0x01, 0x00, // INTEGER[1]: 0
            0x30, 0x10, // SEQUENCE[16]
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID[7]: 1.2.840.10045.2.1
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, // OID[5]: 1.3.132.0.35
            0x04, 0x81, 0xD6, // OCTETSTRING[LONG(1): 214]
            0x30, 0x81, 0xD3, // SEQUENCE[LONG(1): 211]
            0x02, 0x01, 0x01, // INTEGER[1]: 1
            0x04, 0x42 // OCTETSTRING[66]
        ])
        public static let asn1PrefixS2 = Data([
            0xA1, 0x81, 0x89, // CONTEXT SPECIFIC(1)[LONG(1): 137]
            0x03, 0x81, 0x86, // BITSTRING[134]
            0x00 // EOC
        ])
    }
}

extension SecKey {

    var data: Data {
        var error: Unmanaged<CFError>?
        let data: Data! = SecKeyCopyExternalRepresentation(self, &error) as Data?
//        print(data as! CFData)
        return data
    }
}

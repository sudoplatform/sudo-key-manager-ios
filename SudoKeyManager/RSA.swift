//
// Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import ASN1Swift

enum Bit: UInt8, CustomStringConvertible {
    case zero, one

    var description: String {
        switch self {
        case .zero:
            return "0"
        case .one:
            return "1"
        }
    }
    
    init?(rawValue: UInt8) {
        switch rawValue {
        case 0:
            self = .zero
        case 1:
            self = .one
        default:
            return nil
        }
    }
}

extension Int {
    
    /// Encodes an integer as a length of TLV structure in ASN.1.
    ///
    /// - Returns: Encoded length.
    func asn1EncodedLength() -> Data {
        var data = Data()
        if self < 0x80 {
            // Short form (lengths between 0 and 127). Only 1 byte is needed in this case.
            // Bit 7 of the length octet is set to 0, and the length is encoded as an unsigned
            // binary value in the octet's rightmost seven bits. For example, if the length is
            // 5 then the bit layout would be |00000101|.
            data.append(UInt8(self))
            return data
        } else {
            // Long form (lengths between 0 and 21008 octets). First octet contains the length of the length n
            // with bit 7 set to 1. Subsequent n octets represent the actual length of the encoded value. For
            // example, if the length is 257 then the first octet would be |10000010| to indicate that the
            // subsequent 2 octets represent the length. The subsequent 2 octets would then be |000000001|00000001|.
            var bits = self
            var lengthValueCount = 0
            repeat {
                lengthValueCount += 1
                bits >>= 8
            } while bits > 0x0
            
            var lengthBytes = [UInt8(0x80 | lengthValueCount)]
            for i in (0 ..< lengthValueCount).reversed() {
                lengthBytes.append(UInt8((self & Int(0xFF << (i * 8))) >> (i * 8)))
            }
            data.append(contentsOf: lengthBytes)
            return data
        }
    }
    
}

extension UInt8 {
    
    /// Converts `UInt8` value to an array of bits.
    ///
    /// - Returns: Array of bits.
    func bits() -> [Bit] {
        var byte = self
        var bits = [Bit](repeating: .zero, count: 8)
        for i in (0..<8).reversed() {
            if let bit = Bit(rawValue: byte & 0x01) {
                bits[i] = bit
            }
            byte >>= 1
        }
        return bits
    }
    
}

/// Utility class for converting RSAPublicKey to SubjectPublicKeyInfo.
public class RSAPublicKey {

    public struct Tag {
        static let sequence: UInt8 = 0x30
        static let bitString: UInt8 = 0x03
        static let objectIdentifier: UInt8 = 0x06
        static let null: [UInt8] = [0x05, 0x00]
    }
    
    public struct Oid {
        static let rsaEncryption: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    }
    
    public let keyData: Data
    
    /// Converts and returns the encapsulated RSAPublicKey in SubjectPublicKeyInfo format.
    ///
    /// - Returns: Public key encoded in SubjectPublicKeyInfo format.
    public func toSubjectPublicKeyInfo() -> Data {
        // https://datatracker.ietf.org/doc/html/rfc5912
        var publicKey = Data()
        publicKey.append(Tag.bitString)
        publicKey.append((self.keyData.count + 1).asn1EncodedLength())
        publicKey.append(0x00)
        publicKey.append(self.keyData)
        
        var algorithmObjectId = Data()
        algorithmObjectId.append(Tag.objectIdentifier)
        algorithmObjectId.append(Oid.rsaEncryption.count.asn1EncodedLength())
        algorithmObjectId.append(contentsOf: Oid.rsaEncryption)
        
        var algorithm = Data()
        algorithm.append(Tag.sequence)
        algorithm.append((algorithmObjectId.count + Tag.null.count).asn1EncodedLength())
        algorithm.append(algorithmObjectId)
        algorithm.append(contentsOf: Tag.null)
        
        var spki = Data()
        spki.append(Tag.sequence)
        spki.append((algorithm.count + publicKey.count).asn1EncodedLength())
        spki.append(algorithm)
        spki.append(publicKey)
        
        return spki
    }
    
    /// Intializes `RSAPublicKey`.
    ///
    /// - Parameter keyData: Raw key data encoded as RSAPublicKey.
    public init(keyData: Data) {
        self.keyData = keyData
    }
        
}

/// Utility class for converting RSAPrivateKey to PrivateKeyInfo.
public class RSAPrivateKey {

    public struct Tag {
        static let integer: UInt8 = 0x02
        static let sequence: UInt8 = 0x30
        static let octetString: UInt8 = 0x04
        static let objectIdentifier: UInt8 = 0x06
        static let null: [UInt8] = [0x05, 0x00]
    }
    
    public struct Oid {
        static let rsaEncryption: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    }
    
    public let keyData: Data
    
    /// Converts and returns the encapsulated RSAPrivateKey in PrivateKeyInfo format.
    ///
    /// - Returns: Private key encoded in PrivateKeyInfo format.
    public func toPrivateKeyInfo() -> Data {
        // https://datatracker.ietf.org/doc/html/rfc5912
        var privateKey = Data()
        privateKey.append(Tag.octetString)
        privateKey.append((self.keyData.count).asn1EncodedLength())
        privateKey.append(self.keyData)
        
        var algorithmObjectId = Data()
        algorithmObjectId.append(Tag.objectIdentifier)
        algorithmObjectId.append(Oid.rsaEncryption.count.asn1EncodedLength())
        algorithmObjectId.append(contentsOf: Oid.rsaEncryption)
        
        var algorithm = Data()
        algorithm.append(Tag.sequence)
        algorithm.append((algorithmObjectId.count + Tag.null.count).asn1EncodedLength())
        algorithm.append(algorithmObjectId)
        algorithm.append(contentsOf: Tag.null)
        
        var version = Data()
        version.append(Tag.integer)
        version.append(contentsOf: [0x01, 0x00])
        
        var pki = Data()
        pki.append(Tag.sequence)
        pki.append((version.count + algorithm.count + privateKey.count).asn1EncodedLength())
        pki.append(version)
        pki.append(algorithm)
        pki.append(privateKey)
        
        return pki
    }
    
    /// Intializes `RSAPrivateKey`.
    ///
    /// - Parameter keyData: Raw key data encoded as RSAPrivateKey.
    public init(keyData: Data) {
        self.keyData = keyData
    }
        
}


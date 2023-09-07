//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

/// Key attribute value types.
public enum KeyAttributeValue: Hashable {
    case stringValue(String)
    case boolValue(Bool)
    case intValue(Int)
    case dataValue(Data)
    case keyTypeValue(KeyType)
}

/// Supported key types. Declared as String so that when keys are exported the type is easily recognizable.
///
/// - privateKey: RSA private key.
/// - publicKey: RSA public key.
/// - symmetricKey: AES key.
/// - password: Password or any other generic data to store securely.
/// - unknown: Key type is either unspecified or unknown.
public enum KeyType: String {
    case privateKey = "PrivateKey"
    case publicKey = "PublicKey"
    case symmetricKey = "SymmetricKey"
    case password = "Password"
    case unknown = "Unknown"
    
    public init(rawValue: String) {
        // We need to override the default initializer in order to
        // ensure interoperability with JS SDK since it uses different
        // casing for key types.
        switch rawValue.lowercased() {
        case KeyType.privateKey.rawValue.lowercased():
            self = .privateKey
        case KeyType.publicKey.rawValue.lowercased():
            self = .publicKey
        case KeyType.symmetricKey.rawValue.lowercased():
            self = .symmetricKey
        case KeyType.password.rawValue.lowercased():
            self = .password
        default:
            self = .unknown
        }
    }
    
}

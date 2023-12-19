//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Gzip
import ASN1Swift

/// List of possible errors thrown by `SecureKeyArchive` implementation.
///
/// - duplicateKey: Indicates that duplicate keys were found while saving the
///     keys to the secure store.
/// - archiveEmpty: Indicates that unarchive or archive operation was requested
///     but the archive was empty.
/// - invalidPassword: Indicates the password invalid, e.g. empty string.
/// - invalidKeyAttribute: Indicates the archive contained invalid key attribute.
/// - versionMismatch: Indicates the archive being unarchived is not a support
///     version.
/// - fatalError: Indicates that a fatal error occurred. This could be due to
///     coding error, out-of-memory condition or other conditions that is
///     beyond control of `SecureKeyArchive` implementation.
public enum SecureKeyArchiveError : Error {
    case duplicateKey
    case archiveEmpty
    case invalidPassword
    case invalidKeyAttribute
    case invalidArchiveData
    case malformedKeySetData
    case versionMismatch
    case fatalError
}

/// List of key archive attributes.
public enum SecureKeyArchiveAttribute: String {
    case version = "Version"
    case type = "Type"
    case keys = "Keys"
    case salt = "Salt"
    case rounds = "Rounds"
    case iv = "IV"
    case metaInfo = "MetaInfo"
}

/// List of archive types.
public enum SecureKeyArchiveType: String {
    case secure = "Secure"
    case insecure = "Insecure"
}

/// Supported archive versions.
public enum SecureKeyArchiveVersion: Int {
    case v1 = 1
    case v2 = 2
    case v3 = 3
}

struct Algorithm: ASN1Decodable
{
    public var oid: String
    public var parameters: ASN1Null
    
    enum CodingKeys: ASN1CodingKey
    {
        case oid
        case parameters
        
        var template: ASN1Template
        {
            switch self
            {
            case .oid:
                return .universal(ASN1Identifier.Tag.objectIdentifier)
            case .parameters:
                return .universal(ASN1Identifier.Tag.null)
            }
        }
    }
    
    init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.oid = try container.decode(String.self, forKey: .oid)
        self.parameters = try container.decode(ASN1Null.self, forKey: .parameters)
    }
    
    static var template: ASN1Template
    {
        return ASN1Template.universal(ASN1Identifier.Tag.sequence).constructed()
    }
    
}

struct PublicKeyInfo: ASN1Decodable
{
    var algorithm: Algorithm
    var subjectPublicKey: Data
    
    enum CodingKeys: ASN1CodingKey
    {
        case algorithm
        case subjectPublicKey
        
        var template: ASN1Template
        {
            switch self
            {
            case .algorithm:
                return ASN1Template.universal(ASN1Identifier.Tag.sequence).constructed()
            case .subjectPublicKey:
                return ASN1Template.universal(ASN1Identifier.Tag.bitString)
            }
        }
    }
    
    init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.algorithm = try container.decode(Algorithm.self, forKey: .algorithm)
        let data = try container.decode(Data.self, forKey: .subjectPublicKey)
        // The leading byte of bit string indicates the number of unused
        // bits in the last byte of the bit string content. In this case, the
        // last byte is a part of public exponent integer so it's completely
        // used hence the leading byte will always be zero. It's safe to just
        // strip it.
        self.subjectPublicKey = data.advanced(by: 1)
    }
    
    static var template: ASN1Template
    {
        return ASN1Template.universal(ASN1Identifier.Tag.sequence).constructed()
    }
}

struct PrivateKeyInfo: ASN1Decodable
{
    var version: Int
    var algorithm: Algorithm
    var privateKey: Data
    
    enum CodingKeys: ASN1CodingKey
    {
        case version
        case algorithm
        case privateKey
        
        var template: ASN1Template
        {
            switch self
            {
            case .version:
                return ASN1Template.universal(ASN1Identifier.Tag.integer)
            case .algorithm:
                return ASN1Template.universal(ASN1Identifier.Tag.sequence).constructed()
            case .privateKey:
                return ASN1Template.universal(ASN1Identifier.Tag.octetString)
            }
        }
    }
    
    init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.version = try container.decode(Int.self, forKey: .version)
        self.algorithm = try container.decode(Algorithm.self, forKey: .algorithm)
        self.privateKey = try container.decode(Data.self, forKey: .privateKey)
    }
    
    static var template: ASN1Template
    {
        return ASN1Template.universal(ASN1Identifier.Tag.sequence).constructed()
    }
}

/// Protocol encapsulating a set of methods required for creating and
/// processing an encrypt archive for a set of cryptographic keys and
/// passwords.
public protocol SecureKeyArchive {
    
    /// Intializes a new `SecureKeyArchive` instance.
    ///
    /// - Parameter keyManager: `SudoKeyManager` instance for accessing keys.
    init(keyManager: SudoKeyManager)
    
    /// Intializes a new `SecureKeyArchive` instance.
    ///
    /// - Parameters:
    ///   - keyManager: `SudoKeyManager` instance for accessing keys.
    ///   - zip: Indiciates whether or not the archive data should be zipped.
    init(keyManager: SudoKeyManager, zip: Bool)
    
    /// Intializes a new `SecureKeyArchive` instance with archive data.
    ///
    /// - Parameters:
    ///   - archiveData: key archive data.
    ///   - keyManager: `SudoKeyManager` instance.
    init?(archiveData: Data, keyManager: SudoKeyManager)
    
    /// Intializes a new `SecureKeyArchive` instance with archive data.
    ///
    /// - Parameters:
    ///   - archiveData: key archive data.
    ///   - keyManager: `SudoKeyManager` instance.
    ///   - zip: Indiciates whether or not the archive data has been zipped.
    init?(archiveData: Data, keyManager: SudoKeyManager, zip: Bool)
    
    /// Loads keys from the secure store into the archive.
    ///
    /// - Throws:
    ///     `SecureKeyArchiveError.fatalError`
    func loadKeys() throws

    /// Saves the keys in this archive to the secure store.
    /// - Throws:
    ///     `SecureKeyArchiveError.duplicateKey`
    ///     `SecureKeyArchiveError.archiveEmpty`
    ///     `SecureKeyArchiveError.fatalError`
    func saveKeys() throws
    
    /// Archives and encrypts the keys loaded into this archive.
    ///
    /// - Parameter password: Password to use to encrypt the archive. If nil no encryption is performed.
    ///
    /// - Throws:
    ///     `SecureKeyArchiveError.invalidPassword`
    ///     `SecureKeyArchiveError.archiveEmpty`
    ///     `SecureKeyArchiveError.fatalError`
    func archive(_ password: String?) throws -> Data
    
    /// Decrypts and unarchives the keys in this archive.
    ///
    /// - Parameters
    ///     - password: Password to use to decrypt the archive. If nil no decryption is performed.
    ///
    /// - Throws:
    ///     `SecureKeyArchiveError.invalidPassword`
    ///     `SecureKeyArchiveError.archiveEmpty`
    ///     `SecureKeyArchiveError.invalidArchiveData`
    ///     `SecureKeyArchiveError.fatalError`
    func unarchive(_ password: String?) throws
    
    /// Resets the archive by clearing loaded keys and archive data.
    func reset()

    /// Determines whether or not the archive contains the key with the
    /// specified name and type. The archive must be unarchived before the
    /// key can be searched.
    ///
    /// - Parameters:
    ///   - name: Key name.
    ///   - type: Key type.
    ///
    /// - Returns: `true` if the specified key exists in the archive.
    func containsKey(_ name: String, type: KeyType) -> Bool
    
    /// Retrieves the specified key data from the archive. The archive must
    /// be unarchived before the key data can be retrieved.
    ///
    /// - Parameters:
    ///   - name: Key name.
    ///   - type: Key type.
    func getKeyData(_ name: String, type: KeyType) -> Data?
    
    /// Key manager used for managing keys and performing cryptographic operations.
    var keyManager: SudoKeyManager { get set }

    /// List of key names to exclude from the archive.
    var excludedKeys: [String] { get set }

    /// List of key types to exclude from the archive.
    var excludedKeyTypes: [String] { get set }
    
    /// Meta-information associated with this archive.
    var metaInfo: [String: String] { get set }
    
    /// Archive version.
    var version: Int { get }
    
    /// Archive type.
    var type: SecureKeyArchiveType { get }
    
    /// List of key name spaces associated with this archive.
    var namespaces: [String] { get }
    
}

/// Default implementation of `SecureKeyArchive` which loads and
/// saves keys to and from Apple's keychain. The keys are encrypted
/// using AES.
public class SecureKeyArchiveImpl {
        
    /// List of contants used by this class.
    fileprivate struct Constants {
        
        /// Initialization vector size in bytes for AES encryption.
        static let ivSize = 16
        
    }

    public var excludedKeys: [String] = []

    public var excludedKeyTypes: [String] = []
    
    public var metaInfo: [String: String] = [:]
    
    public fileprivate(set) var namespaces: [String] = []

    /// Keys associated with this archive.
    public fileprivate(set) var keys: [[KeyAttributeName: AnyObject]] = []
        
    /// Archive version.
    public fileprivate(set) var version = 2
    
    /// Archive type.
    public fileprivate(set) var type = SecureKeyArchiveType.secure

    public var keyManager: SudoKeyManager

    /// Encrypted archive data.
    fileprivate var archiveData: Data?
    
    /// Dictionary representing the deserialized content of an archive.
    fileprivate var archiveDictionary: [SecureKeyArchiveAttribute: AnyObject] = [:]
    
    /// Indicates whether or not the archive uses gzip compression.
    fileprivate var zip = false

    /// Logger.
    fileprivate let logger = Logger.sharedInstance
    
    // ASN.1 decoder.
    fileprivate let asn1Decoder = ASN1Decoder()
    
    public required convenience init(keyManager: SudoKeyManager) {
        self.init(keyManager: keyManager, zip: false)
    }
    
    public required init(keyManager: SudoKeyManager, zip: Bool) {
        self.keyManager = keyManager
        self.zip = zip
        if self.zip {
            // If we are using zip then it must be v3 archive.
            self.version = SecureKeyArchiveVersion.v3.rawValue
        }
    }

    public required init?(archiveData: Data, keyManager: SudoKeyManager, zip: Bool) {
        self.keyManager = keyManager
        self.archiveData = archiveData
        self.zip = zip
       
        if self.zip {
            do {
                self.archiveData = try self.archiveData?.gunzipped()
            } catch {
                self.logger.log(.error, message: "Failed to unzip archive data: \(error)")
                return nil
            }
        }
        
        guard let archiveDictionary = self.archiveData?.toJSONObject() as? [String: AnyObject] else {
            return nil
        }
        
        // Convert String keys to Enum keys.
        for (k, v) in archiveDictionary {
            guard let enumKey = SecureKeyArchiveAttribute(rawValue: k) else {
                continue
            }
            
            self.archiveDictionary[enumKey] = v
        }
        
        // Meta info might be needed before the archive is unarchived.
        if let metaInfo = self.archiveDictionary[.metaInfo] as? [String: String] {
            self.metaInfo = metaInfo
        }
    }
    
    public required convenience init?(archiveData: Data, keyManager: SudoKeyManager) {
        self.init(archiveData: archiveData, keyManager: keyManager, zip: false)
    }
        
}

// MARK: SecureKeyArchive

extension SecureKeyArchiveImpl: SecureKeyArchive {
        
    public func loadKeys() throws {
        do {
            let keys = try self.keyManager.exportKeys()
            
            for var key in keys {
                if let name = key[.name] as? String,
                   !self.excludedKeys.contains(name),
                    let keyType = key[.type] as? String,
                   !self.excludedKeyTypes.contains(keyType) {
                    if let namespace = key[.namespace] as? String, !namespace.isEmpty, !namespaces.contains(namespace) {
                        namespaces.append(namespace)
                    }
                    if self.zip {
                        // If we are dealing with v3 archive then we need to convert the
                        // format of public and private keys since JS SDK uses different
                        // formats.
                        if let type = key[.type] as? String {
                            if KeyType(rawValue: type) == KeyType.privateKey {
                                if let encodedData = key[.data] as? String, let data = Data(base64Encoded: encodedData) {
                                    let rsaPrivateKey = RSAPrivateKey(keyData: data)
                                    key[.data] = rsaPrivateKey.toPrivateKeyInfo().base64EncodedString() as AnyObject
                                }
                            } else if KeyType(rawValue: type) == KeyType.publicKey {
                                if let encodedData = key[.data] as? String, let data = Data(base64Encoded: encodedData) {
                                    let rsaPublicKey = RSAPublicKey(keyData: data)
                                    key[.data] = rsaPublicKey.toSubjectPublicKeyInfo().base64EncodedString() as AnyObject
                                }
                            }
                        }
                    }
                    self.keys.append(key)
                }
            }
        } catch let error {
            self.logger.log(.error, message: "Failed to export keys from the secure store: \(error)")
            throw SecureKeyArchiveError.fatalError
        }
    }
    
    public func saveKeys() throws {
        guard self.keys.count > 0 else {
            throw SecureKeyArchiveError.archiveEmpty
        }
        
        // Remove all keys first otherwise we will get key conflicts.
        try self.keyManager.removeAllKeys()
        
        do {
            var keys: [[KeyAttributeName: AnyObject]] = []
            
            for var key in self.keys {
                if let name = key[.name] as? String, !self.excludedKeys.contains(name) {
                    if self.zip {
                        // If we are dealing with v3 archive then we need to convert the
                        // format of public and private keys since JS SDK uses different
                        // formats.
                        if let type = key[.type] as? String {
                            if KeyType(rawValue: type) == KeyType.privateKey {
                                if let encodedData = key[.data] as? String, let data = Data(base64Encoded: encodedData) {
                                    let privateKeyInfo = try asn1Decoder.decode(PrivateKeyInfo.self, from: data)
                                    key[.data] = privateKeyInfo.privateKey.base64EncodedString() as AnyObject
                                }
                            } else if KeyType(rawValue: type) == KeyType.publicKey {
                                if let encodedData = key[.data] as? String, let data = Data(base64Encoded: encodedData) {
                                    let publicKeyInfo = try asn1Decoder.decode(PublicKeyInfo.self, from: data)
                                    key[.data] = publicKeyInfo.subjectPublicKey.base64EncodedString() as AnyObject
                                }
                            }
                        }
                    }
                    keys.append(key)
                }
            }
            
            try self.keyManager.importKeys(keys)
        } catch SudoKeyManagerError.duplicateKey {
            throw SecureKeyArchiveError.duplicateKey
        } catch {
            self.logger.log(.error, message: "Failed to import keys into the secure store: \(error)")
            throw SecureKeyArchiveError.fatalError
        }
    }
    
    public func archive(_ password: String?) throws -> Data {
        return try self.archive(password, iv: nil)
    }
    
    public func archive(_ password: String?, iv: Data?) throws -> Data {
        guard self.keys.count > 0 else {
            throw SecureKeyArchiveError.archiveEmpty
        }
        
        self.archiveDictionary = [.version: self.version as AnyObject, .metaInfo: self.metaInfo as AnyObject]
        
        // Convert Enum keys to String keys satisfy the requirements for JSON serializer.
        var keys: [[String: AnyObject]] = []
        for dictionary in self.keys {
            keys.append(Dictionary(dictionary.map { (k, v) in (k.rawValue, v) }))
        }
        
        guard var data = keys.toJSONData() else {
            throw SecureKeyArchiveError.fatalError
        }
        
        if let password = password {
            guard !password.isEmpty else {
                throw SecureKeyArchiveError.invalidPassword
            }

            do {
                let (key, salt, rounds) = try self.keyManager.createSymmetricKeyFromPassword(password)
                self.archiveDictionary[.type] = SecureKeyArchiveType.secure.rawValue as AnyObject
                self.archiveDictionary[.salt] = salt.base64EncodedString() as AnyObject
                self.archiveDictionary[.rounds] = NSNumber(value: rounds as UInt32)
                
                let encryptedData: Data
                if self.zip {
                    // V3 archive requires you to zip the input to encryption.
                    data = try data.gzipped(level: .bestCompression)
                    
                    // Random IV is not necessary for secure archives but JS SDK uses it so we need to
                    // be consistent for interop. The use of non default IV also makes V3 secure archive
                    // not compatible with AES-GCM.
                    let random = try self.keyManager.createRandomData(Constants.ivSize)
                    encryptedData = try self.keyManager.encryptWithSymmetricKey(key, data: data, iv: random)
                    self.archiveDictionary[.iv] = random.base64EncodedString() as AnyObject
                } else {
                    encryptedData = try self.keyManager.encryptWithSymmetricKey(key, data: data)
                }
                
                self.archiveDictionary[.keys] = encryptedData.base64EncodedString() as AnyObject
            } catch {
                self.logger.log(.error, message: "Failed to encrypted the key archive: \(error)")
                throw SecureKeyArchiveError.fatalError
            }
        } else {
            self.archiveDictionary[.type] = SecureKeyArchiveType.insecure.rawValue as AnyObject
            if self.zip {
                self.archiveDictionary[.keys] = keys as AnyObject
            } else {
                self.archiveDictionary[.keys] = data.base64EncodedString() as AnyObject
            }
        }
        
        // Convert Enum keys to String keys satisfy the requirements for JSON serializer.
        guard var archiveData = Dictionary(self.archiveDictionary.map { (k, v) in (k.rawValue, v) }).toJSONData() else {
            throw SecureKeyArchiveError.fatalError
        }
        
        if self.zip {
            archiveData = try archiveData.gzipped(level: .bestCompression)
        }
        return archiveData
    }
    
    public func unarchive(_ password: String?) throws {
        guard let version = self.archiveDictionary[.version] as? Int else {
            throw SecureKeyArchiveError.invalidArchiveData
        }
                
        self.version = version
        
        guard let supportedVersion = SecureKeyArchiveVersion(rawValue: self.version) else {
            throw SecureKeyArchiveError.versionMismatch
        }
        
        if let type = self.archiveDictionary[.type] as? String {
            guard let supportedType = SecureKeyArchiveType(rawValue: type) else {
                throw SecureKeyArchiveError.invalidArchiveData
            }
            
            self.type = supportedType
        }
        
        let keys: [[String: AnyObject]]?
        if let password = password {
            guard
                let keysStr = self.archiveDictionary[.keys] as? String,
                var keysData = Data(base64Encoded: keysStr),
                let saltStr = self.archiveDictionary[.salt] as? String,
                let salt = Data(base64Encoded: saltStr),
                let rounds = self.archiveDictionary[.rounds] as? NSNumber else {
                throw SecureKeyArchiveError.invalidArchiveData
            }
            
            guard !password.isEmpty else {
                throw SecureKeyArchiveError.invalidPassword
            }

            do {
                let key = try self.keyManager.createSymmetricKeyFromPassword(password, salt: salt, rounds: UInt32(rounds.uintValue))
                
                // Random IV is not necessary for secure archives but JS SDK uses it so we need to
                // be consistent for interop. The use of non default IV also makes V3 secure archive
                // not compatible with AES-GCM.
                if let ivStr = self.archiveDictionary[.iv] as? String, let iv = Data(base64Encoded: ivStr) {
                    keysData = try self.keyManager.decryptWithSymmetricKey(key, data: keysData, iv: iv)
                } else {
                    keysData = try self.keyManager.decryptWithSymmetricKey(key, data: keysData)
                }
                                
                if self.zip {
                    // V3 encrypted archive is zipped twice so we need to unzip one more time.
                    keysData = try keysData.gunzipped()
                }
                keys = keysData.toJSONObject() as? [[String: AnyObject]]
            } catch {
                self.logger.log(.error, message: "Failed to decrypt the key archive: \(error)")
                throw SecureKeyArchiveError.fatalError
            }
        } else {
            if supportedVersion == SecureKeyArchiveVersion.v3 {
                keys = self.archiveDictionary[.keys] as? [[String: AnyObject]]
            } else {
                guard
                    let keysStr = self.archiveDictionary[.keys] as? String,
                    let keysData = Data(base64Encoded: keysStr) else {
                    throw SecureKeyArchiveError.invalidArchiveData
                }
                keys = keysData.toJSONObject() as? [[String: AnyObject]]
            }
        }
       
        guard let keys = keys else {
            throw SecureKeyArchiveError.malformedKeySetData
        }
        
        self.keys.removeAll()
        
        // Convert all String keys to Enum keys. We can't use simple mapping here
        // since a String key may fail to convert to Enum key.
        for element in keys {
            var dictionary: [KeyAttributeName: AnyObject] = [:]
            for key in element.keys {
                guard let newKey = KeyAttributeName(rawValue: key) else {
                    throw SecureKeyArchiveError.invalidKeyAttribute
                }
                
                dictionary[newKey] = element[key]
            }
            
            if let namespace = dictionary[.namespace] as? String, !namespace.isEmpty, !self.namespaces.contains(namespace) {
                self.namespaces.append(namespace)
            }
            
            self.keys.append(dictionary)
        }
    }
    
    public func reset() {
        self.keys.removeAll()
        self.archiveData = nil
    }
    
    public func containsKey(_ name: String, type: KeyType) -> Bool {
        return getKeyData(name, type: type) != nil
    }
    
    public func getKeyData(_ name: String, type: KeyType) -> Data? {
        var keyData: Data?
        
        for key in self.keys {
            if let namespace = key[.namespace] as? String, namespace == self.keyManager.namespace,
                let keyName = key[.name] as? String, keyName == name,
                let keyType = key[.type] as? String, keyType == type.rawValue,
                let encodedData = key[.data] as? String,
                let data = Data(base64Encoded: encodedData) {
                keyData = data
                break
            }
        }
        
        return keyData
    }
    
}
   

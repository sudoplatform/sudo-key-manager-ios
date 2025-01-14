//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
import SudoKeyManager

class SudoKeyManagerTests: XCTestCase {
    
    fileprivate var keys: [[KeyAttributeName: AnyObject]]?
    
    fileprivate let keyManager: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "myapp")
    
    fileprivate let legacyKeyManager: SudoKeyManager = LegacySudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "myapp")
    
    fileprivate let keyManagerTestNamespace: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "test")
    
    override func setUp() {
        super.setUp()
        self.continueAfterFailure = false
        
        do {
            try self.keyManager.removeAllKeys()
            try self.keyManagerTestNamespace.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
    }
    
    override func tearDown() {
        super.tearDown()
        
        do {
            try self.keyManager.removeAllKeys()
            try self.keyManagerTestNamespace.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
    }
    
    func testKeyAttribute() {
        let attr1 = KeyAttribute(name: .type, value: .keyTypeValue(.password))
        let attr2 = KeyAttribute(name: .type, value: .keyTypeValue(.password))
        let attr3 = KeyAttribute(name: .type, value: .keyTypeValue(.privateKey))

        switch attr1.value {
        case .keyTypeValue(let value):
            XCTAssertEqual(KeyType.password, value)
        default:
            XCTFail("Attribute value has incorrect type.")
        }
        XCTAssertEqual(attr1, attr2)
        XCTAssertNotEqual(attr1, attr3)
        
        let attr4 = KeyAttribute(name: .synchronizable, value: .boolValue(true))
        let attr5 = KeyAttribute(name: .synchronizable, value: .boolValue(true))
        let attr6 = KeyAttribute(name: .synchronizable, value: .boolValue(false))
        let attr7 = KeyAttribute(name: .exportable, value: .boolValue(true))
        
        switch attr4.value {
        case .boolValue(let value):
            XCTAssertTrue(value)
        default:
            XCTFail("Attribute value has incorrect type.")
        }
        XCTAssertEqual(attr4, attr5)
        XCTAssertNotEqual(attr4, attr6)
        XCTAssertNotEqual(attr4, attr7)
        
        let attr8 = KeyAttribute(name: .id, value: .stringValue("id1"))
        let attr9 = KeyAttribute(name: .id, value: .stringValue("id1"))
        let attr10 = KeyAttribute(name: .id, value: .stringValue("id2"))
        
        switch attr8.value {
        case .stringValue(let value):
            XCTAssertEqual("id1", value)
        default:
            XCTFail("Attribute value has incorrect type.")
        }
        XCTAssertEqual(attr8, attr9)
        XCTAssertNotEqual(attr8, attr10)

        let attr11 = KeyAttribute(name: .id, value: .dataValue("dummy_data1".data(using: String.Encoding.utf8)!))
        let attr12 = KeyAttribute(name: .id, value: .dataValue("dummy_data1".data(using: String.Encoding.utf8)!))
        let attr13 = KeyAttribute(name: .id, value: .dataValue("dummy_data2".data(using: String.Encoding.utf8)!))
        
        switch attr11.value {
        case .dataValue(let value):
            XCTAssertEqual("dummy_data1", String(data: value, encoding: .utf8))
        default:
            XCTFail("Attribute value has incorrect type.")
        }
        XCTAssertEqual(attr11, attr12)
        XCTAssertNotEqual(attr11, attr13)
        
        let attr14 = KeyAttribute(name: .version, value: .intValue(1))
        let attr15 = KeyAttribute(name: .version, value: .intValue(1))
        let attr16 = KeyAttribute(name: .version, value: .intValue(2))
        
        switch attr14.value {
        case .intValue(let value):
            XCTAssertEqual(1, value)
        default:
            XCTFail("Attribute value has incorrect type.")
        }
        XCTAssertEqual(attr14, attr15)
        XCTAssertNotEqual(attr14, attr16)
    }
    
    func testKeyAttributes() {
        var keyAttributes1 = KeyAttributeSet()
        keyAttributes1.addAttribute(.id, value: .stringValue("dummy_id"))
        keyAttributes1.addAttribute(.type, value: .keyTypeValue(.privateKey))
        keyAttributes1.addAttribute(.synchronizable, value: .boolValue(true))
        
        XCTAssertEqual(3, keyAttributes1.count)
        
        if let attribute = keyAttributes1.getAttribute(.id) {
            XCTAssertEqual(KeyAttributeValue.stringValue("dummy_id"), attribute.value)
        } else {
            XCTFail("Key attribute not found.")
        }
        
        if let attribute = keyAttributes1.getAttribute(.type) {
            XCTAssertEqual(KeyAttributeValue.keyTypeValue(.privateKey), attribute.value)
        } else {
            XCTFail("Key attribute not found.")
        }
        
        if let attribute = keyAttributes1.getAttribute(.synchronizable) {
            XCTAssertEqual(KeyAttributeValue.boolValue(true), attribute.value)
        } else {
            XCTFail("Key attribute not found.")
        }
        
        var keyAttributes3 = KeyAttributeSet()
        keyAttributes3.addAttribute(.id, value: .stringValue("dummy_id"))
        keyAttributes3.addAttribute(.synchronizable, value: .boolValue(true))
        
        var keyAttributes4 = KeyAttributeSet()
        keyAttributes4.addAttribute(.id, value: .stringValue("dummy_id"))
        keyAttributes4.addAttribute(.type, value: .keyTypeValue(.privateKey))
        
        var keyAttributes5 = KeyAttributeSet()
        keyAttributes5.addAttribute(.type, value: .keyTypeValue(.privateKey))
        keyAttributes5.addAttribute(.synchronizable, value: .boolValue(true))
        
        var keyAttributes6 = KeyAttributeSet()
        keyAttributes6.addAttribute(.synchronizable, value: .boolValue(false))

        var keyAttributes7 = KeyAttributeSet()
        keyAttributes7.addAttribute(.type, value: .keyTypeValue(.publicKey))

        var keyAttributes8 = KeyAttributeSet()
        keyAttributes8.addAttribute(.id, value: .stringValue("dummy_id2"))

        XCTAssertTrue(keyAttributes3.isSubsetOf(keyAttributes1))
        XCTAssertTrue(keyAttributes4.isSubsetOf(keyAttributes1))
        XCTAssertTrue(keyAttributes5.isSubsetOf(keyAttributes1))
        XCTAssertFalse(keyAttributes6.isSubsetOf(keyAttributes1))
        XCTAssertFalse(keyAttributes7.isSubsetOf(keyAttributes1))
        XCTAssertFalse(keyAttributes8.isSubsetOf(keyAttributes1))
        
        var keyAttributes9 = KeyAttributeSet()
        keyAttributes9.addAttribute(.id, value: .stringValue("dummy_id"))

        var keyAttributes10 = KeyAttributeSet()
        keyAttributes10.addAttribute(.type, value: .keyTypeValue(.privateKey))

        var keyAttributes11 = KeyAttributeSet()
        keyAttributes11.addAttribute(.synchronizable, value: .boolValue(true))
        
        XCTAssertEqual(keyAttributes10, keyAttributes1.subtract(keyAttributes3))
        XCTAssertEqual(keyAttributes11, keyAttributes1.subtract(keyAttributes4))
        XCTAssertEqual(keyAttributes9, keyAttributes1.subtract(keyAttributes5))
    }
    
    func testKeyAttributesIsSearchable() {
        var keyAttributes1 = KeyAttributeSet()
        keyAttributes1.addAttribute(.synchronizable, value: .boolValue(true))
        keyAttributes1.addAttribute(.type, value: .keyTypeValue(.privateKey))
        var keyAttributes2 = KeyAttributeSet()
        keyAttributes2.addAttribute(.data, value: .dataValue("dummy_data".data(using: String.Encoding.utf8)!))
        var keyAttributes3 = KeyAttributeSet()
        keyAttributes3.addAttribute(.type, value: .keyTypeValue(.privateKey))
        keyAttributes3.addAttribute(.namespace, value: .stringValue("dummy_namespace"))
        
        XCTAssertTrue(keyAttributes1.isSearchable())
        XCTAssertFalse(keyAttributes2.isSearchable())
        XCTAssertFalse(keyAttributes3.isSearchable())
    }
    
    func testKeyAttributesIsMutable() {
        var keyAttributes1 = KeyAttributeSet()
        keyAttributes1.addAttribute(.synchronizable, value: .boolValue(true))
        keyAttributes1.addAttribute(.exportable, value: .boolValue(true))
        var keyAttributes2 = KeyAttributeSet()
        keyAttributes2.addAttribute(.namespace, value: .stringValue("dummy_namespace"))
        var keyAttributes3 = KeyAttributeSet()
        keyAttributes3.addAttribute(.synchronizable, value: .boolValue(true))
        keyAttributes3.addAttribute(.namespace, value: .stringValue("dummy_namespace"))
        
        XCTAssertTrue(keyAttributes1.isMutable())
        XCTAssertFalse(keyAttributes2.isMutable())
        XCTAssertFalse(keyAttributes3.isMutable())
    }
    
    func testPassword() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("dummy_key_id") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            try self.keyManager.updatePassword("passw1rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to update password: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("dummy_key_id") {
                XCTAssertEqual("passw1rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            try self.keyManager.deletePassword("dummy_key_id")
        } catch let error {
            XCTFail("Failed to delete password: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("dummy_key_id")
            XCTAssertNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
    }
    
    func testSynchronizablePassword() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id", isSynchronizable: true, isExportable: true)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("dummy_key_id") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            try self.keyManager.updatePassword("passw1rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to update password: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("dummy_key_id") {
                XCTAssertEqual("passw1rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            try self.keyManager.deletePassword("dummy_key_id")
        } catch let error {
            XCTFail("Failed to delete password: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("dummy_key_id")
            XCTAssertNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
    }
    
    func testSymmetricKey() {
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            if let keyData = try self.keyManager.getSymmetricKey("dummy_key_id") {
                XCTAssertNotNil(keyData)
            } else {
                XCTFail("Symmetric key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.deleteSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to delete symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
    }
    
    func testSymmetricKeyCrypto() {
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        var data: Data?
        do {
            data = try self.keyManager.encryptWithSymmetricKey("dummy_key_id", data: "dummy_plaintext".data(using: String.Encoding.utf8)!)
        } catch let error {
            XCTFail("Failed to encrypt: \(error)")
        }
        
        guard let ciphertext = data else {
            XCTFail("Encryption produced nil ciphertext.")
            return
        }
        
        do {
            let plaintext = try self.keyManager.decryptWithSymmetricKey("dummy_key_id", data: ciphertext)
            XCTAssertEqual("dummy_plaintext".data(using: String.Encoding.utf8)!, plaintext)
        } catch let error {
            XCTFail("Failed to decrypt: \(error)")
        }
    }
    
    func testKeyPair() {
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            if let keyData = try self.keyManager.getPrivateKey("dummy_key_id") {
                XCTAssertNotNil(keyData)
            } else {
                XCTFail("Private key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            if let keyData = try self.keyManager.getPublicKey("dummy_key_id") {
                XCTAssertNotNil(keyData)
            } else {
                XCTFail("Public key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
        
        do {
            try self.keyManager.deleteKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to delete key pair: \(error)")
        }
        
        do {
            let key = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNil(key)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let key = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNil(key)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testRemoveAllKeys() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("dummy_key_id")
            XCTAssertNotNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("dummy_key_id")
            XCTAssertNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }

    }
    
    func testExportKeys() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_sync_key_id", isSynchronizable: true, isExportable: true)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "myapp.dummy_key_id.myapp")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            let keys = try self.keyManager.exportKeys()
            XCTAssertNotNil(keys)
            XCTAssertEqual(5, keys.count)
            self.keys = keys
        } catch let error {
            XCTFail("Failed to export keys: \(error)")
        }
    }
    
    func testImportKeys() {
        testExportKeys()
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        if let keys = self.keys {
            do {
                try self.keyManager.importKeys(keys)
            } catch let error {
                XCTFail("Failed to import keys: \(error)")
            }
        } else {
            XCTFail("Failed to export keys.")
        }
        
        do {
            let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp")
            XCTAssertNotNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("dummy_sync_key_id")
            XCTAssertNotNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testPasswordCrypto() {
        var keyTuple = (key: Data(), salt: Data(), rounds: UInt32(0))
        do {
            keyTuple = try self.keyManager.createSymmetricKeyFromPassword("passw0rd")
        } catch let error {
            XCTFail("Failed to create a key from password: \(error)")
        }
        
        var data: Data?
        do {
            data = try self.keyManager.encryptWithSymmetricKey(keyTuple.key, data: "dummy_plaintext".data(using: String.Encoding.utf8)!)
        } catch let error {
            XCTFail("Failed to encrypt: \(error)")
        }
        
        guard let ciphertext = data else {
            XCTFail("Encryption produced nil ciphertext.")
            return
        }
        
        do {
            let plaintext = try self.keyManager.decryptWithSymmetricKey(keyTuple.key, data: ciphertext)
            XCTAssertEqual("dummy_plaintext".data(using: String.Encoding.utf8)!, plaintext)
        } catch let error {
            XCTFail("Failed to decrypt: \(error)")
        }
    }
    
    func testSignatureValidation() {
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        let data = "dummy_plaintext".data(using: String.Encoding.utf8)!
        
        var signature: Data?
        do {
            signature = try self.keyManager.generateSignatureWithPrivateKey("dummy_key_id", data: data)
        } catch let error {
            XCTFail("Failed to generate signature with private key: \(error)")
        }
        
        do {
            let status = try self.keyManager.verifySignatureWithPublicKey("dummy_key_id", data: data, signature: signature!)
            XCTAssertTrue(status)
        } catch let error {
            XCTFail("Failed to generate signature with public key: \(error)")
        }
    }
    
    func testPrivatePublicKeyCrypto() {
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        let data = "dummy_plaintext".data(using: String.Encoding.utf8)!
        
        var encryptedData: Data?
        do {
            encryptedData = try self.keyManager.encryptWithPublicKey("dummy_key_id", data: data)
        } catch let error {
            XCTFail("Failed to encrypt data with public key: \(error)")
        }
        
        do {
            let decryptedData = try self.keyManager.decryptWithPrivateKey("dummy_key_id", data: encryptedData!)
            XCTAssertNotNil(decryptedData)
            XCTAssertEqual("dummy_plaintext", String(data: decryptedData, encoding: String.Encoding.utf8))
        } catch let error {
            XCTFail("Failed to decrypt data with private key: \(error)")
        }
    }

    func testPrivatePublicKeyCryptoWithKeyData() {
        let keyId = "dummy_key_id"
        do {
            try self.keyManager.generateKeyPair(keyId)
        } catch {
            XCTFail("Failed to generate a key pair: \(error)")
        }

        var keyData: Data!
        do {
            let publicKeyData = try self.keyManager.getPublicKey(keyId)
            XCTAssertNotNil(publicKeyData)
            keyData = publicKeyData!
        } catch {
            XCTFail("Failed to get generated public key: \(error)")
        }

        let data = "dummy_plaintext".data(using: String.Encoding.utf8)!

        var encryptedData: Data?
        do {
            encryptedData = try self.keyManager.encryptWithPublicKey(keyData, data: data)
        } catch {
            XCTFail("Failed to encrypt data with public key: \(error)")
        }

        do {
            let decryptedData = try self.keyManager.decryptWithPrivateKey(keyId, data: encryptedData!)
            XCTAssertNotNil(decryptedData)
            XCTAssertEqual("dummy_plaintext", String(data: decryptedData, encoding: String.Encoding.utf8))
        } catch {
            XCTFail("Failed to decrypt data with private key: \(error)")
        }
    }

    func testPrivatePublicKeyCryptoOAEP() {
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        let data = "dummy_plaintext".data(using: String.Encoding.utf8)!
        
        var encryptedData: Data?
        do {
            encryptedData = try self.keyManager.encryptWithPublicKey("dummy_key_id", data: data, algorithm: .rsaEncryptionOAEPSHA1)
        } catch let error {
            XCTFail("Failed to encrypt data with public key: \(error)")
        }
        
        do {
            let decryptedData = try self.keyManager.decryptWithPrivateKey("dummy_key_id", data: encryptedData!, algorithm: .rsaEncryptionOAEPSHA1)
            XCTAssertNotNil(decryptedData)
            XCTAssertEqual("dummy_plaintext", String(data: decryptedData, encoding: String.Encoding.utf8))
        } catch let error {
            XCTFail("Failed to decrypt data with private key: \(error)")
        }
    }
    
    func testPrivatePublicKeyCryptoWithMultipleBlocks() {
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        var plaintext = "0123456789"
        
        for  _ in 1...100 {
            plaintext.append("0123456789")
        }
        
        let data = plaintext.data(using: String.Encoding.utf8)!
        
        var encryptedData: Data?
        do {
            encryptedData = try self.keyManager.encryptWithPublicKey("dummy_key_id", data: data)
        } catch let error {
            XCTFail("Failed to encrypt data with public key: \(error)")
        }
        
        do {
            let decryptedData = try self.keyManager.decryptWithPrivateKey("dummy_key_id", data: encryptedData!)
            XCTAssertNotNil(decryptedData)
            XCTAssertEqual(plaintext, String(data: decryptedData, encoding: String.Encoding.utf8))
        } catch let error {
            XCTFail("Failed to decrypt data with private key: \(error)")
        }
    }

    func testUpdateKey() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.synchronizable, value : .boolValue(true))
            try self.keyManager.updateKeyAttributes(updates, name: "dummy_key_id", type: .password)
        } catch let error {
            XCTFail("Failed to update key attributes: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.synchronizable, value : .boolValue(false))
            try self.keyManager.updateKeyAttributes(updates, name: "dummy_key_id", type: .password)
        } catch let error {
            XCTFail("Failed to update key attributes: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
    }
    
    func testUpdateKeyId() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let keyId = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp.dummy_key_id"), keyId.value)
                } else {
                    XCTFail("Key ID attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.id, value : .stringValue("test.dummy_key_id2"))
            try self.keyManager.updateKeyAttributes(updates, name: "dummy_key_id", type: .password)
        } catch let error {
            XCTFail("Failed to update key attributes: \(error)")
        }
        
        do {
            // We had changed the key ID to have a different namespace and key name so use a SudoKeyManager instance
            // with the different namespace to retrieve the key with the new ID.
            if let attributes = try self.keyManagerTestNamespace.getKeyAttributes("dummy_key_id2", type: .password) {
                if let keyId = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("test.dummy_key_id2"), keyId.value)
                } else {
                    XCTFail("Key ID attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
    }
    
    func testUpdateExportable() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Exportable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.exportable, value : .boolValue(false))
            try self.keyManager.updateKeyAttributes(updates, name: "dummy_key_id", type: .password)
        } catch let error {
            XCTFail("Failed to update key attributes: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), exportable.value)
                } else {
                    XCTFail("Exportable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.exportable, value : .boolValue(true))
            try self.keyManager.updateKeyAttributes(updates, name: "dummy_key_id", type: .password)
        } catch let error {
            XCTFail("Failed to update key attributes: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Exportable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
    }
    
    func testGetKeyId() {
        XCTAssertEqual("myapp.key1", try self.keyManager.getKeyId("key1", type: .password))
        XCTAssertEqual("com.sudoplatform.privatekey.myapp.key2", try self.keyManager.getKeyId("key2", type: .privateKey))
        XCTAssertEqual("com.sudoplatform.publickey.myapp.key3", try self.keyManager.getKeyId("key3", type: .publicKey))
        XCTAssertEqual("com.sudoplatform.myapp.key4", try self.keyManager.getKeyId("key4", type: .symmetricKey))
    }
    
    
    func testResetSecureStore() {
        let keyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "myapp")
        
        do {
            try keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "myapp.dummy_key_id.myapp")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try keyManager.generateSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            try keyManager.resetSecureKeyStore()
        } catch let error {
            XCTFail("Failed to reset secure key store: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp")
            XCTAssertNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testNonExportableKey() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_sync_key_id", isSynchronizable: true, isExportable: true)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "myapp.dummy_key_id.myapp", isSynchronizable: true, isExportable: true)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id", isExportable: true)
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.addSymmetricKey(self.keyManager.getSymmetricKey("dummy_key_id")!, name: "dummy_key_id2", isExportable: true)
        } catch let error {
            XCTFail("Failed to add symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("dummy_key_id", isExportable: true)
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            try self.keyManager.addPrivateKey(self.keyManager.getPrivateKey("dummy_key_id")!, name: "dummy_key_id2", isExportable: true)
        } catch let error {
            XCTFail("Failed to add private key: \(error)")
        }
        
        do {
            try self.keyManager.addPublicKey(self.keyManager.getPublicKey("dummy_key_id")!, name: "dummy_key_id2", isExportable: true)
        } catch let error {
            XCTFail("Failed to add public key: \(error)")
        }
        
        do {
            let keys = try self.keyManager.exportKeys()
            XCTAssertNotNil(keys)
            XCTAssertEqual(8, keys.count)
            self.keys = keys
        } catch let error {
            XCTFail("Failed to export keys: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove keys: \(error)")
        }
    
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_sync_key_id", isSynchronizable: true, isExportable: false)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "myapp.dummy_key_id.myapp", isSynchronizable: true, isExportable: false)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id", isExportable: false)
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.addSymmetricKey(self.keyManager.getSymmetricKey("dummy_key_id")!, name: "dummy_key_id2", isExportable: false)
        } catch let error {
            XCTFail("Failed to add symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("dummy_key_id", isExportable: false)
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            try self.keyManager.addPrivateKey(self.keyManager.getPrivateKey("dummy_key_id")!, name: "dummy_key_id2", isExportable: false)
        } catch let error {
            XCTFail("Failed to add private key: \(error)")
        }
        
        do {
            try self.keyManager.addPublicKey(self.keyManager.getPublicKey("dummy_key_id")!, name: "dummy_key_id2", isExportable: false)
        } catch let error {
            XCTFail("Failed to add public key: \(error)")
        }
        
        do {
            let keys = try self.keyManager.exportKeys()
            XCTAssertNotNil(keys)
            XCTAssertEqual(0, keys.count)
            self.keys = keys
        } catch let error {
            XCTFail("Failed to export keys: \(error)")
        }
    }
    
    func testGetKeyAttributes() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_sync_password", isSynchronizable: true, isExportable: false)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_sync_password", type: .password) {
                if let name = attributes.getAttribute(.name) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("dummy_sync_password"), name.value)
                } else {
                    XCTFail("Name attribute not found.")
                }
                
                if let id = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp.dummy_sync_password"), id.value)
                } else {
                    XCTFail("Id attribute not found.")
                }
                
                if let namespace = attributes.getAttribute(.namespace) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), namespace.value)
                } else {
                    XCTFail("Namespace attribute not found.")
                }
                
                if let type = attributes.getAttribute(.type) {
                    XCTAssertEqual(KeyAttributeValue.keyTypeValue(.password), type.value)
                } else {
                    XCTFail("Type attribute not found.")
                }
                
                if let version = attributes.getAttribute(.version) {
                    XCTAssertEqual(KeyAttributeValue.intValue(1), version.value)
                } else {
                    XCTFail("Version attribute not found.")
                }
                
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), exportable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_password", isSynchronizable: false, isExportable: true)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_password", type: .password) {
                if let name = attributes.getAttribute(.name) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("dummy_password"), name.value)
                } else {
                    XCTFail("Name attribute not found.")
                }
                
                if let id = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp.dummy_password"), id.value)
                } else {
                    XCTFail("Id attribute not found.")
                }
                
                if let namespace = attributes.getAttribute(.namespace) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), namespace.value)
                } else {
                    XCTFail("Namespace attribute not found.")
                }
                
                if let type = attributes.getAttribute(.type) {
                    XCTAssertEqual(KeyAttributeValue.keyTypeValue(.password), type.value)
                } else {
                    XCTFail("Type attribute not found.")
                }
                
                if let version = attributes.getAttribute(.version) {
                    XCTAssertEqual(KeyAttributeValue.intValue(1), version.value)
                } else {
                    XCTFail("Version attribute not found.")
                }
                
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("dummy_symmetric_key")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_symmetric_key", type: .symmetricKey) {
                if let name = attributes.getAttribute(.name) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("dummy_symmetric_key"), name.value)
                } else {
                    XCTFail("Name attribute not found.")
                }
                
                if let id = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("com.sudoplatform.myapp.dummy_symmetric_key"), id.value)
                } else {
                    XCTFail("Id attribute not found.")
                }
                
                if let namespace = attributes.getAttribute(.namespace) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), namespace.value)
                } else {
                    XCTFail("Namespace attribute not found.")
                }
                
                if let type = attributes.getAttribute(.type) {
                    XCTAssertEqual(KeyAttributeValue.keyTypeValue(.symmetricKey), type.value)
                } else {
                    XCTFail("Type attribute not found.")
                }
                
                if let version = attributes.getAttribute(.version) {
                    XCTAssertEqual(KeyAttributeValue.intValue(1), version.value)
                } else {
                    XCTFail("Version attribute not found.")
                }
                
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("dummy_keypair")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_keypair", type: .privateKey) {
                if let name = attributes.getAttribute(.name) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("dummy_keypair"), name.value)
                } else {
                    XCTFail("Name attribute not found.")
                }
                
                if let id = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("com.sudoplatform.privatekey.myapp.dummy_keypair"), id.value)
                } else {
                    XCTFail("Id attribute not found.")
                }
                
                if let namespace = attributes.getAttribute(.namespace) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), namespace.value)
                } else {
                    XCTFail("Namespace attribute not found.")
                }
                
                if let type = attributes.getAttribute(.type) {
                    XCTAssertEqual(KeyAttributeValue.keyTypeValue(.privateKey), type.value)
                } else {
                    XCTFail("Type attribute not found.")
                }
                
                if let version = attributes.getAttribute(.version) {
                    XCTAssertEqual(KeyAttributeValue.intValue(1), version.value)
                } else {
                    XCTFail("Version attribute not found.")
                }
                
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_keypair", type: .publicKey) {
                if let name = attributes.getAttribute(.name) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("dummy_keypair"), name.value)
                } else {
                    XCTFail("Name attribute not found.")
                }
                
                if let id = attributes.getAttribute(.id) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("com.sudoplatform.publickey.myapp.dummy_keypair"), id.value)
                } else {
                    XCTFail("Id attribute not found.")
                }
                
                if let namespace = attributes.getAttribute(.namespace) {
                    XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), namespace.value)
                } else {
                    XCTFail("Namespace attribute not found.")
                }
                
                if let type = attributes.getAttribute(.type) {
                    XCTAssertEqual(KeyAttributeValue.keyTypeValue(.publicKey), type.value)
                } else {
                    XCTFail("Type attribute not found.")
                }
                
                if let version = attributes.getAttribute(.version) {
                    XCTAssertEqual(KeyAttributeValue.intValue(1), version.value)
                } else {
                    XCTFail("Version attribute not found.")
                }
                
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            let attributesArray = try self.keyManager.getAttributesForKeys(KeyAttributeSet())
            XCTAssertEqual(5, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_sync_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_symmetric_key"), .keyTypeValue(.symmetricKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.privateKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.publicKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name or type.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.synchronizable, value: .boolValue(true))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(1, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_sync_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name or type.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.synchronizable, value: .boolValue(false))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(4, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_symmetric_key"), .keyTypeValue(.symmetricKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.privateKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.publicKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name or type.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.exportable, value: .boolValue(false))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(1, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_sync_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name or type.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.exportable, value: .boolValue(true))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(4, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_symmetric_key"), .keyTypeValue(.symmetricKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.privateKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.publicKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.type, value: .keyTypeValue(.password))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(2, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_sync_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.exportable)?.value)
                    case (.stringValue("dummy_password"), .keyTypeValue(.password)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.type, value: .keyTypeValue(.symmetricKey))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(1, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_symmetric_key"), .keyTypeValue(.symmetricKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.type, value: .keyTypeValue(.privateKey))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(1, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.privateKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
        
        do {
            var searchAttributes = KeyAttributeSet()
            searchAttributes.addAttribute(.type, value: .keyTypeValue(.publicKey))
            let attributesArray = try self.keyManager.getAttributesForKeys(searchAttributes)
            XCTAssertEqual(1, attributesArray.count)
            for attributes in attributesArray {
                if let name = attributes.getAttribute(.name), let type = attributes.getAttribute(.type) {
                    switch (name.value, type.value) {
                    case (.stringValue("dummy_keypair"), .keyTypeValue(.publicKey)):
                        XCTAssertEqual(KeyAttributeValue.intValue(1), attributes.getAttribute(.version)?.value)
                        XCTAssertEqual(KeyAttributeValue.stringValue("myapp"), attributes.getAttribute(.namespace)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(false), attributes.getAttribute(.synchronizable)?.value)
                        XCTAssertEqual(KeyAttributeValue.boolValue(true), attributes.getAttribute(.exportable)?.value)
                    default:
                        XCTFail("Invalid key name.")
                    }
                } else {
                    XCTFail("Invalid key attributes.")
                    break
                }
            }
        } catch let error {
            XCTFail("Failed to retrieve key attributes: \(error)")
        }
    }
    
    func testGenerateKeyId() {
        do {
            let keyId1 = try keyManager.generateKeyId()
            let keyId2 = try keyManager.generateKeyId()
            XCTAssertNotEqual(keyId1, keyId2)
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testGenerateHashInterOp() {
        do {
            let data = "dummy_data".data(using: .utf8)!
            let hash1 = try keyManager.generateHash(data)
            let hash2 = try legacyKeyManager.generateHash(data)
            XCTAssertEqual(hash1, hash2)
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testDeletePrivateOrPublicKey() {
        do {
            try keyManager.generateKeyPair("dummy_key_id")
            XCTAssertNotNil(try keyManager.getPrivateKey("dummy_key_id"))
            XCTAssertNotNil(try keyManager.getPublicKey("dummy_key_id"))
            
            try keyManager.deletePrivateKey("dummy_key_id")
            XCTAssertNil(try keyManager.getPrivateKey("dummy_key_id"))
            XCTAssertNotNil(try keyManager.getPublicKey("dummy_key_id"))
            
            try keyManager.deletePublicKey("dummy_key_id")
            XCTAssertNil(try keyManager.getPublicKey("dummy_key_id"))
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
 
    func testPEMPublicKey() {
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        var publicKey: String? = nil
        do {
            publicKey = try self.keyManager.getPublicKeyAsPEM("dummy_key_id")
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
        
        guard let publicKey = publicKey else {
            return XCTFail("Public key not found")
        }
        
        do {
            try self.keyManager.deletePublicKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to delete public key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
        
        do {
            try self.keyManager.addPublicKeyFromPEM(publicKey, name: "dummy_key_id")
        } catch let error {
            XCTFail("Failed to add public key: \(error)")
        }
        
        let data = "dummy_plaintext".data(using: String.Encoding.utf8)!
        
        var encryptedData: Data?
        do {
            encryptedData = try self.keyManager.encryptWithPublicKey("dummy_key_id", data: data)
        } catch let error {
            XCTFail("Failed to encrypt with public key: \(error)")
        }
        
        do {
            let decryptedData = try self.keyManager.decryptWithPrivateKey("dummy_key_id", data: encryptedData!)
            XCTAssertNotNil(decryptedData)
            XCTAssertEqual("dummy_plaintext", String(data: decryptedData, encoding: String.Encoding.utf8))
        } catch let error {
            XCTFail("Failed to decrypt with private key: \(error)")
        }
    }
    
}

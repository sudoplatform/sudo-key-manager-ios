//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
import SudoKeyManager

class SecureKeyArchiveTests: XCTestCase {
    
    fileprivate let keyManager: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "myapp")
    
    fileprivate let interOpKeyManager: SudoKeyManager = LegacySudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "SudoDistributedVaultClient")
    
    fileprivate let anotherSudoKeyManager: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "anotherapp")
    
    override func setUp() {
        super.setUp()
        self.continueAfterFailure = false
        
        do {
            try self.keyManager.removeAllKeys()
            try self.anotherSudoKeyManager.removeAllKeys()
            try self.interOpKeyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
    }
    
    override func tearDown() {
        super.tearDown()
        
        do {
            try self.keyManager.removeAllKeys()
            try self.anotherSudoKeyManager.removeAllKeys()
            try self.interOpKeyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
    }

    func testKeyArchive() {
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
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
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive("passw0rd")
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive("passw0rd")
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
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
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
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

    func testKeyArchiveExcludingKeyType() {
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        archive.excludedKeyTypes = [KeyType.publicKey.rawValue]
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
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
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive("passw0rd")
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive("passw0rd")
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
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
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
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
            XCTAssertNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }

    func testKeyArchiveV3() {
        let keyManager: SudoKeyManager = LegacySudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "myapp")
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: keyManager, zip: true)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        
        do {
            try keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_sync_key_id", isSynchronizable: true, isExportable: true)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
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
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive("passw0rd")
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: keyManager, zip: true)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive("passw0rd")
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        do {
            try keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let password = try keyManager.getPassword("dummy_sync_key_id")
            XCTAssertNotNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            if let password = try keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try keyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testKeyArchiveWithMultipleNameSpaces() {
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
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
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        XCTAssertEqual(["myapp"], archive.namespaces)
        
        do {
            try self.anotherSudoKeyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.anotherSudoKeyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "anotherapp.dummy_key_id.anotherapp")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.anotherSudoKeyManager.generateSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.anotherSudoKeyManager.generateKeyPair("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        archive.keyManager = self.anotherSudoKeyManager
        
        do {
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        XCTAssertEqual(["myapp", "anotherapp"], archive.namespaces)
        
        var data: Data?
        do {
            data = try archive.archive("passw0rd")
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        var newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive("passw0rd")
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        XCTAssertEqual(["myapp", "anotherapp"], newArchive.namespaces)
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
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
        
        // Make sure the key set under a different namespace is untouched by the import.
        do {
            if let password = try self.anotherSudoKeyManager.getPassword("anotherapp.dummy_key_id.anotherapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.anotherSudoKeyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.anotherSudoKeyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.anotherSudoKeyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
        
        // Now try to import the keys with the other namespace.
        newArchive.keyManager = self.anotherSudoKeyManager
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            if let password = try self.anotherSudoKeyManager.getPassword("anotherapp.dummy_key_id.anotherapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.anotherSudoKeyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.anotherSudoKeyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.anotherSudoKeyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
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
    }
    
    func testContainsKey() {
        let archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "password")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("symmetric")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("keypair")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }

        do {
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive("passw0rd")
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        do {
            try newArchive.unarchive("passw0rd")
            XCTAssertTrue(newArchive.containsKey("password", type: .password))
            XCTAssertTrue(newArchive.containsKey("symmetric", type: .symmetricKey))
            XCTAssertTrue(newArchive.containsKey("keypair", type: .privateKey))
            XCTAssertTrue(newArchive.containsKey("keypair", type: .publicKey))
            XCTAssertFalse(newArchive.containsKey("password", type: .privateKey))
            XCTAssertFalse(newArchive.containsKey("password1", type: .password))
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
    }

    func testGetKeyData() {
        let archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "password")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive("passw0rd")
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        do {
            try newArchive.unarchive("passw0rd")
            guard let password = newArchive.getKeyData("password", type: .password), String(data: password, encoding: String.Encoding.utf8) == "passw0rd" else {
                XCTFail("Password not found in the key archive.")
                return
            }
            
            XCTAssertNil(newArchive.getKeyData("password1", type: .password))
            XCTAssertNil(newArchive.getKeyData("password", type: .privateKey))
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
    }
    
    func testBadIV() {
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
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
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            var iv = Data(count: 16)
            iv[0] = 0x10
            iv[4] = 0x01
            
            data = try (archive as! SecureKeyArchiveImpl).archive("passw0rd", iv: iv)
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive("passw0rd")
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
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
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
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
    
    func testInsecureKeyArchive() {
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
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

        var symmetricKey: Data? = nil
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id")
            symmetricKey = try self.keyManager.getSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        XCTAssertNotNil(symmetricKey)
        
        var privateKey: Data? = nil
        var publicKey: Data? = nil
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
            privateKey = try self.keyManager.getPrivateKey("dummy_key_id")
            publicKey = try self.keyManager.getPublicKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        XCTAssertNotNil(privateKey)
        XCTAssertNotNil(publicKey)
        
        do {
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive(nil)
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive(nil)
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
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
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
            XCTAssertEqual(symmetricKey, keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
            XCTAssertEqual(privateKey, keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
            XCTAssertEqual(publicKey, keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testInsecureKeyArchiveV3() {
        var archive: SecureKeyArchive = SecureKeyArchiveImpl(keyManager: self.keyManager, zip: true)
        
        archive.metaInfo = ["appNames": "SUDO"]
        archive.excludedKeys = ["excluded_key_id"]
        
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "excluded_key_id")
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
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

        var symmetricKey: Data? = nil
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id")
            symmetricKey = try self.keyManager.getSymmetricKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        XCTAssertNotNil(symmetricKey)
        
        var privateKey: Data? = nil
        var publicKey: Data? = nil
        do {
            try self.keyManager.generateKeyPair("dummy_key_id")
            privateKey = try self.keyManager.getPrivateKey("dummy_key_id")
            publicKey = try self.keyManager.getPublicKey("dummy_key_id")
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        XCTAssertNotNil(privateKey)
        XCTAssertNotNil(publicKey)
        
        do {
            try archive.loadKeys()
        } catch let error {
            XCTFail("Failed to load keys: \(error)")
        }
        
        var data: Data?
        do {
            data = try archive.archive(nil)
        } catch let error {
            XCTFail("Failed to archive keys: \(error)")
        }
        
        guard let archiveData = data else {
            XCTFail("Failed to archive keys.")
            return
        }
        
        let newArchive: SecureKeyArchive = SecureKeyArchiveImpl(archiveData: archiveData, keyManager: self.keyManager, zip: true)!
        XCTAssertEqual(["appNames": "SUDO"], newArchive.metaInfo)
        do {
            try newArchive.unarchive(nil)
        } catch let error {
            XCTFail("Failed to unarchive keys: \(error)")
        }
        
        do {
            try self.keyManager.removeAllKeys()
        } catch let error {
            XCTFail("Failed to remove all keys: \(error)")
        }
        
        do {
            try newArchive.saveKeys()
        } catch let error {
            XCTFail("Failed to save keys: \(error)")
        }
        
        do {
            let password = try self.keyManager.getPassword("excluded_key_id")
            XCTAssertNil(password)
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
            if let password = try self.keyManager.getPassword("myapp.dummy_key_id.myapp") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getSymmetricKey("dummy_key_id")
            XCTAssertNotNil(keyData)
            XCTAssertEqual(symmetricKey, keyData)
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPrivateKey("dummy_key_id")
            XCTAssertNotNil(keyData)
            XCTAssertEqual(privateKey, keyData)
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            let keyData = try self.keyManager.getPublicKey("dummy_key_id")
            XCTAssertNotNil(keyData)
            XCTAssertEqual(publicKey, keyData)
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testV3InsecureKeyArchiveInterop() {
        // V3 insecure key archive from another platform. Don't update it since the point of this is
        // to check that we have not broken backward compatibility (with existing key backups) and
        // interoperability with all clients.
        let exportedKeys = "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"
        
        do {
            let archive = SecureKeyArchiveImpl(archiveData: Data(base64Encoded: exportedKeys)!, keyManager: self.interOpKeyManager, zip: true)
            try archive?.unarchive(nil)
            XCTAssertEqual(SecureKeyArchiveType.insecure, archive?.type)
            XCTAssertEqual(3, archive?.version)
            try archive?.saveKeys()
            
            guard let privateKey = try self.interOpKeyManager.getPrivateKey("452a3efd-d605-4dd0-bba2-b7f94ab9d4d2") else {
                return XCTFail("Private key not found.")
            }
            XCTAssertEqual("MIIEowIBAAKCAQEAqT6HQB6BphL/Fec+frwI7pD0iKfx11lX75ooWHDwY1KDDVYQodgq8Kzy11GPUSZA+DbcAK15yC8cRkG7Q6WWphBn4CXkNPppKEoTupcKLJQabyQAhEc7+BX4S065LUTvb1CGQjqqd4vbDmGjg7Llt+n31zqJvoHTraZyx9P8mVTCmLFig8GRmEZSw2aApNrUOjpZaoLAWStbHEJuhFVe23Yi/JnHUtl6VafQqfVKX3nuskm2Cca4AzLqZB7EeH+LnE1hXBmvcWeEclNjzlt5s5gOdSjA+iaftoqHKmI3MxJQVt3I1sbl0pv4Ig/p+9n9QrGSbOrfjgVHiJmMUOFI6QIDAQABAoIBAQCUHWfqgog+WoOpnJ4B9ffvKScI7cnmCIe/5m8Gr5iBo/WTV03pBjDWPtWsAPHnOA5F7GTvpuJcgnZBOkdz9Vf5b4QpE6A7iSc8nk/TzVmXF+pmd+CH43ulKz0IUxYWeyz8g0FsdsE3LEuCs4qRuJ/4K6e+Ubm44w/o+jGblneLi8kDI6vGutCUNmIqXO98jD3Wbg4BBnTmpBv7+VoQOAzKRiJA2CQSxtE60l+XEBD5S2vApkV5cXtFdPEaEcQ4oSkZsAExplt45uUsfj/pHnSa/H0hv/QaXfRg9EB8rKUV8yMY/1i0rsj7DV91uFgORlgSsWV7oBIrLTUKGOM3l3ztAoGBANJ+MhnOGaECAvwQNWH4t9mH0YNd2v1Im2KPOeO0QBm/22eL95WA6MhWPQp9I+V3UJVPnsOqRccnhZzl4atzu0Q7t0fTYb6/nmeRfmzyFqq359RIUe2EiLngsPjsKl8FpdacZFTo9xyp5igHAYPfOdcBb+LifPm8w3MLTH5rJEjTAoGBAM3VaMDFBDlqp88MbcPdwf8E28R7JBh40/tag8glj8zLbZ0NlFKYbMmcYmBnCBIuGORs5vz/TtukygpM9D1oPdCTKlpjpI84j8nkdpZ2S6715h5AOTSCxS+gC3olAO6TpOpUyoKSxfsrAwKWL28IDUY2gIjTKbFm+gxWyCwQR9HTAoGAXCTUJ8m6HGp2BgPOapnnWXmENN6UK8ZqBwYt0EkqulrrX/O8qRyqSnC9/eZ0HVJS21nkZUEXlKvvaJSVammaM690dyPIqSjW3f2p+2UqmQcynBIgkzouZDhBIGa50aj2RPFnVmg5LLoPP7x5ZFIGzuEZKpf9H5ILeUQb80dRtfMCgYBCzALWrBkW2PnkQ1BLw+d07wqy1JN+LZf9df5WMXpdJ5dG5GVB+J01QD7cshL4c2U4m+7KI8BfnzbB6P9J/k4xJdEUzElXATAIgM/LPFCLUtl+77Cgzd9X+URAO0n2IoveT+34OdFuFSNA76QtEBvesUk9Henl3FlBL9h+FDp6aQKBgHMpRCCFOVdbh0+yuHf8dhzC5ZvNY7//Q68hht6h1iHiFmtpOr92ThURTEVvhsQ4irvQHgPjfIQoWdxiW/T7FcDMos40c9/HEw2KDZ8k+Rj0mvsJHn8iI4CJjZbNgHWw4GuCpH+/QrLm9H5LHxtIINNb9EZKCL3SsseE1yOWFK8p", privateKey.base64EncodedString())
            
            guard let publicKey = try self.interOpKeyManager.getPublicKey("452a3efd-d605-4dd0-bba2-b7f94ab9d4d2") else {
                return XCTFail("Public key not found.")
            }
            XCTAssertEqual("MIIBCgKCAQEAqT6HQB6BphL/Fec+frwI7pD0iKfx11lX75ooWHDwY1KDDVYQodgq8Kzy11GPUSZA+DbcAK15yC8cRkG7Q6WWphBn4CXkNPppKEoTupcKLJQabyQAhEc7+BX4S065LUTvb1CGQjqqd4vbDmGjg7Llt+n31zqJvoHTraZyx9P8mVTCmLFig8GRmEZSw2aApNrUOjpZaoLAWStbHEJuhFVe23Yi/JnHUtl6VafQqfVKX3nuskm2Cca4AzLqZB7EeH+LnE1hXBmvcWeEclNjzlt5s5gOdSjA+iaftoqHKmI3MxJQVt3I1sbl0pv4Ig/p+9n9QrGSbOrfjgVHiJmMUOFI6QIDAQAB", publicKey.base64EncodedString())
            
            let signature = try self.interOpKeyManager.generateSignatureWithPrivateKey("452a3efd-d605-4dd0-bba2-b7f94ab9d4d2", data: "dummy_data".data(using: .utf8)!)
            XCTAssertTrue(try self.interOpKeyManager.verifySignatureWithPublicKey("452a3efd-d605-4dd0-bba2-b7f94ab9d4d2", data: "dummy_data".data(using: .utf8)!, signature: signature))
            
            guard let symmetricKey = try self.interOpKeyManager.getSymmetricKey("953b8fcb-215a-47a5-b128-2b6c20886eda") else {
                return XCTFail("Symmetric key not found.")
            }
            XCTAssertEqual("IUtucXrlZBPYdQyq/8qiOlfBjLfJYbXLwLD31DuoTDU=", symmetricKey.base64EncodedString())
            
            let encrypted = try self.interOpKeyManager.encryptWithSymmetricKey("953b8fcb-215a-47a5-b128-2b6c20886eda", data: "dummy_data".data(using: .utf8)!)
            let decrypted = try self.interOpKeyManager.decryptWithSymmetricKey("953b8fcb-215a-47a5-b128-2b6c20886eda", data: encrypted)
            XCTAssertEqual("dummy_data", String(data: decrypted, encoding: .utf8))
            
            guard let data = try self.interOpKeyManager.getPassword("currentSymmetricKeyId") else {
                return XCTFail("Password not found.")
            }
            XCTAssertEqual("953b8fcb-215a-47a5-b128-2b6c20886eda", String(data: data, encoding: .utf8))
        } catch {
            XCTFail("Failed to process a key archive: \(error)")
        }
    }
    
    func testV3SecureKeyArchiveInterop() {
        // V3 insecure key archive from another platform. Don't update it since the point of this is
        // to check that we have not broken backward compatibility (with existing key backups) and
        // interoperability with all clients.
        let exportedKeys = "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"
        
        do {
            let archive = SecureKeyArchiveImpl(archiveData: Data(base64Encoded: exportedKeys)!, keyManager: self.interOpKeyManager, zip: true)
            try archive?.unarchive("passw0rd")
            XCTAssertEqual(SecureKeyArchiveType.secure, archive?.type)
            XCTAssertEqual(3, archive?.version)
            try archive?.saveKeys()
            XCTAssertNotNil(try self.interOpKeyManager.getPrivateKey("246cc3ab-e8c7-4247-ad97-57692268b961"))
            XCTAssertNotNil(try self.interOpKeyManager.getPublicKey("246cc3ab-e8c7-4247-ad97-57692268b961"))
            XCTAssertNotNil(try self.interOpKeyManager.getSymmetricKey("972592bd-b996-4499-8958-fb29be9c1775"))
            
            guard let privateKey = try self.interOpKeyManager.getPrivateKey("246cc3ab-e8c7-4247-ad97-57692268b961") else {
                return XCTFail("Private key not found.")
            }
            XCTAssertEqual("MIIEowIBAAKCAQEAoWb6Rk8KIHYmqRHCt4+CgUFFr4mAd+Cejar31rWByLZYfs1MrEETI/NgYyhVUAkj1c50mwQFi7LvgNcD+5Vlsnt/ZhySrzYWMNEhjk8OnKcxBSOpazM1krJKDqDjXhdB2pIkUKFthAj3637a7gcl+iVZffuEmXaCe7oRW1pBKiSwlx17H3IS1W8dCAZc2YB6nGHtL+IDuuAS8UqbeYftdMo1eW9YNoQj7CPGtYe6yIqPGNnuUtnz1QVGiup7U7vskYDEVT+Umoggv6zxXq7EnTsew7JZ5QJdFEkMyXhEHTs+ciGzxFO9U8iB+kxaLmsQRnOPo9vE98UEO8w4pZHrDwIDAQABAoIBAQCUSl3F/VarjoJksem55wObqBHTfrzm5xwlwyAkR+1vMIHMNumsFbn1POWhFOyVNWCUTzR5PE+wE33TXTnOi2u9eZQKiFQI4OOwhGSVMHOXYFE8jJBa6tjc6Cv8lrtvtmSN4dm1rytEtUy7NHkHWs/8rRY1FsK0kNq/vKu3yAu5IDiWoZKtjjjd5GCH7Hj4nRQlfTtcF3f/fOupXZ5pCiK9NGyApBwp2R1uMflYSJeSer9PubL8BIwe0Gsgf8f5aRoojtziuCOl1moKwuIatGFIA+GWHiO9xm8/3bARMP8CeLVfKdPxYL6FG388F9FyKUYA1P8JOkjLcKJe5EaHdnPBAoGBANWrV7Sk6WZDOS/+qaGw0NgKmtJbhjAsuYDpg3+QzXWM9aq8narOVXjsaMwfSpFuXJXgEpCRqFInVYnUbyO+fOK/lyERcVctoA18vde2Yiqwu1qMMDrS2Oj84oXxaRhfddyLAMYm7EgRUNw7LcbxoPporhY1wtWWMY4x7SowTtihAoGBAMFgzycorKy06kr6Yki6OuAGBc2rq/94T4ihAe40xQwXvZOBCPp5tMLr1ebarlbK84LSbA5xWNj0tOuKPYWwxC/M/CfdXjwkO/Ajcnhc68e9yU7BHapxMCdjMqQMbgxR9w744eGS0sOR67OBox/JO5oLAytjIZhu8xwLE3WnQrWvAoGAOoqriQ7189LPRFsd1vM/BTJCoQf6iBB48t0H7leaM27fkFwFRtsph+wd+m9IWvhF3bp626lM2NV2FkFiAgUa6nVbzu+cgio6A/f9e7C4zMGHU5O9UyCZ1ZwT5Gb0SH0/KaHcIG5hpo03/l8od62UUYeEywkHzMVN5ou/UyPRNoECgYBody/xa5u8wQ9A6fpmZ5SeqSJBdVg5bnkoyjIMyR0Z50lWggKjrVPlaRno2IIOCR17sskFFF529ds20zthGZkiaY5eysu5mal3lO6l7yzAftpdXR31kaf93yzgSoa4yR66S+FaxsJtPEskcgf5h/BWy1QvACKKAoX6xFEC4hS7qQKBgGECjzBGMrp7r0TNaP95nrwR9zeGHeCvXJxdwG24to/utMG17GSCSkYaGtxm+C0QykF2a7iIXa5H0eH3vc0B2s5AAk7iGxXp73v0Rvvww6AiWKvyvJnCi63xnXktIEy8iKIArmOU1idq3+YNCw+ouEayqbdz/NPqGsvrka4CuDMu", privateKey.base64EncodedString())
            
            guard let publicKey = try self.interOpKeyManager.getPublicKey("246cc3ab-e8c7-4247-ad97-57692268b961") else {
                return XCTFail("Public key not found.")
            }
            XCTAssertEqual("MIIBCgKCAQEAoWb6Rk8KIHYmqRHCt4+CgUFFr4mAd+Cejar31rWByLZYfs1MrEETI/NgYyhVUAkj1c50mwQFi7LvgNcD+5Vlsnt/ZhySrzYWMNEhjk8OnKcxBSOpazM1krJKDqDjXhdB2pIkUKFthAj3637a7gcl+iVZffuEmXaCe7oRW1pBKiSwlx17H3IS1W8dCAZc2YB6nGHtL+IDuuAS8UqbeYftdMo1eW9YNoQj7CPGtYe6yIqPGNnuUtnz1QVGiup7U7vskYDEVT+Umoggv6zxXq7EnTsew7JZ5QJdFEkMyXhEHTs+ciGzxFO9U8iB+kxaLmsQRnOPo9vE98UEO8w4pZHrDwIDAQAB", publicKey.base64EncodedString())
            
            let signature = try self.interOpKeyManager.generateSignatureWithPrivateKey("246cc3ab-e8c7-4247-ad97-57692268b961", data: "dummy_data".data(using: .utf8)!)
            XCTAssertTrue(try self.interOpKeyManager.verifySignatureWithPublicKey("246cc3ab-e8c7-4247-ad97-57692268b961", data: "dummy_data".data(using: .utf8)!, signature: signature))
            
            guard let symmetricKey = try self.interOpKeyManager.getSymmetricKey("972592bd-b996-4499-8958-fb29be9c1775") else {
                return XCTFail("Symmetric key not found.")
            }
            XCTAssertEqual("ZR/VGltDGu7+Dxugv1t06xFvtPxVckwbTLrNzNw/Fxs=", symmetricKey.base64EncodedString())
            
            let encrypted = try self.interOpKeyManager.encryptWithSymmetricKey("972592bd-b996-4499-8958-fb29be9c1775", data: "dummy_data".data(using: .utf8)!)
            let decrypted = try self.interOpKeyManager.decryptWithSymmetricKey("972592bd-b996-4499-8958-fb29be9c1775", data: encrypted)
            XCTAssertEqual("dummy_data", String(data: decrypted, encoding: .utf8))
            
            guard let data = try self.interOpKeyManager.getPassword("currentSymmetricKeyId") else {
                return XCTFail("Password not found.")
            }
            XCTAssertEqual("972592bd-b996-4499-8958-fb29be9c1775", String(data: data, encoding: .utf8))
        } catch {
            XCTFail("Failed to process a key archive: \(error)")
        }
    }

    func testKeyArchiveFromAndroidInterop() {
        let exportedKeys = "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"

        do {
            let tempKeyManager: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "email-integration-tests")
            let archive = SecureKeyArchiveImpl(archiveData: Data(base64Encoded: exportedKeys)!, keyManager: tempKeyManager, zip: true)
            try archive?.unarchive(nil)
            XCTAssertEqual(SecureKeyArchiveType.insecure, archive?.type)
            XCTAssertEqual(3, archive?.version)
            try archive?.saveKeys()

            guard let privateKey = try tempKeyManager.getPrivateKey("19c035bd-60f9-499c-98ec-f9d195d926e4") else {
                return XCTFail("Private key not found.")
            }
            XCTAssertEqual("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3Uj+V2/LBkVETJHdSST0Ey67CzM4aadCjpRaULTLUDyQ+giIeQVJ3wpFbaOK0Zanro6ffSLEl1BwXSCaHqcxFnr+nAWhrcpE4K2HSeI3U6RmvcQ3CZ4AIzrUa8lCwL5bLtIsdKvVcLBSkZgAzgMQ3KiAXlWWZMcPIzI6SHzke4QhaiIu2LtfH4wKhEx/dYm2wl5TszsRyw0nACz9ypISE0KJM/g0GX1bnxPWBjzS/d7ieJloOkAh5Y9gdJH/RNW2CmaFRiP7g0/mCpHlRzf2NS3tnRiAqPIM5GuaHS9sIDXliYQS+IsKGZRMwvIW2cpD8UBOs/zIju+KMrVY3WsudAgMBAAECggEACe10lOaXICKWOnw8+6dh3E61IrFUJQE0zl6RmTR/E5WpVRBCOD4PMP3yq2RZSJiBKfS60dWeMEoAZnC0E3Xfd9K3wXEgU5dIpCXR85kEjJ09/0QBpn+T4wY3WmOjzn1umWP9gkwcraE+fJkAgEmEIWemMBjD/9aT1MiNHP5/Xvu29wiux+9oyAyxqqwNn4Y8HxvXZbQpXpnrVnDvSiPtVmBATbsIQhP0dn8iWJzJYL+VAFYk6LA4cEXgSFwFGkWsKDz7ZrYPNlKYmp51de3LcBF4zBjDkqgVFKR9x20VLLF/581ddc+Id4hIjyp6kWoGCgMRcL8GWXa77ZK+iv2VUQKBgQD1pGqV3D2jZblmeAdi3ibPVfTz7S53lID4ZxVPXrNJXiBbHC2AiDgmu1fmsCRYE6GBrl2Q5CYd4j9ELucVL8hirc9Y1cqbouxmocpn69FweoBULwAeEZSC+hxde0xtK893V7wOtQSqGUASGrBYKIWbGtHOi1PBxKQpevUyMB2qkQKBgQC/DRvW/qMmIOKu7h3jV1n8wtsMEv7E2gfS3QHoL6YuF260K51wRoZELOlymAoXsK2wWHRSBFAk8fINR9K8sFx/0Qwd756VUkumMaoWwZfH/x0/kjqTPgPccNHeICypBKQmmjbYglvWe0nL711KbsOppDjUPcwhrtub+mcG1xmeTQKBgCt6fqMn6IETcE2C0Uvepl/shv7l7GOeFXXiSRNTX8iMsI1v313wvn+ciWJ7qvMsBlo90rHisBx5/1jCNIS7gGx290xyCvqhS9aerITYaKnQBQbhitPHqNHGE184g76PEpm9Hbw8riatcXnC35O7GGrrxFcasiiJ9cShzuSjP50BAoGAPGJ+TCPLmT+Hplaop7RyQsurxFM0py9qjaFA+wwkcCkD2np2logT4/R2DLw1ZGt5WmV6znmCg0rdgIkU+IKdmeCO/d9Atl1+f5bu9aZWvOXLbs5fKS7OtZwLGTP+KaXH5FOVxjTdphrtpkGPsPj1aub2905Y+MR1sQUiDy1pcXkCgYBOenJho1Rf3h9iid429XeoIxadnpKmSNwFdxTCiJ+2FUUeQHJNnTR4Zja4aNbrEv7DGzVOc58JpFQp7X9vfaNOvR83xP6kqM0Gh1Kl9DMSKJ5ljS11tdD6FZ43GnlhEFoi3dHx/EqB3WcW6BpTs/DIqjlROpTrrcuYPUMWGSAHfw==", privateKey.base64EncodedString())

            guard let symmetricKey = try tempKeyManager.getSymmetricKey("cfcb1e95-e388-40cf-86c3-9f3f151ec140") else {
                return XCTFail("Symmetric key not found.")
            }
            XCTAssertEqual("Kzf/qCc1TNHrNW/yOP6fqbpu8MKROe+R60Ab1czn+Y4=", symmetricKey.base64EncodedString())

            let encrypted = try tempKeyManager.encryptWithSymmetricKey("cfcb1e95-e388-40cf-86c3-9f3f151ec140", data: "dummy_data".data(using: .utf8)!)
            let decrypted = try tempKeyManager.decryptWithSymmetricKey("cfcb1e95-e388-40cf-86c3-9f3f151ec140", data: encrypted)
            XCTAssertEqual("dummy_data", String(data: decrypted, encoding: .utf8))

            guard let data = try tempKeyManager.getPassword("eml-secret-key") else {
                return XCTFail("Password not found.")
            }
            XCTAssertEqual("cfcb1e95-e388-40cf-86c3-9f3f151ec140", String(data: data, encoding: .utf8))
        } catch {
            XCTFail("Failed to process a key archive: \(error)")
        }
    }
}

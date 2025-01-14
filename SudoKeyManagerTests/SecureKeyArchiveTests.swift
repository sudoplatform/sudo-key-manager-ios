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
    
}

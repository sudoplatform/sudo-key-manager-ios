//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
import SudoKeyManager

class MigrationTest: XCTestCase {

    fileprivate let keyManager: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "myapp")
    
    fileprivate let keyManagerTestNamespace: SudoKeyManager = DefaultSudoKeyManager(serviceName: "com.sudoplatform.appservicename", keyTag: "com.sudoplatform", namespace: "test")
    
    fileprivate let migrationManager: MigrationManager = MigrationManagerImpl()
    
    fileprivate var expectation: XCTestExpectation?
    
    fileprivate struct Constants {
        
        static let ExpectationTimeout: TimeInterval = 5.0
        
    }

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

    // The following three methods are to be used as follows:
    // 1. Call `createCompletionExpectation`,
    // 2. Perform some async callback task that has a completion, ensuring that `fulfillCompletionExpectation` is called within the completion.
    // 3. Call `waitForCompletionExpectation` after the completion.
    //
    // Any other order cannot guarantee the behaviour and may crash.

    func createCompletionExpectation() {
        self.expectation = self.expectation(description: "Completion Expectation")
    }
    
    func fulfillCompletionExpectation() {
        if let expectation = self.expectation {
            expectation.fulfill()
        }
    }
    
    func waitForCompletionExpectation() {
        guard let expectation = self.expectation else {
            XCTFail("Expected expectation")
            abort()
        }
        self.wait(for: [expectation], timeout: Constants.ExpectationTimeout)
        self.expectation = nil
    }

    func testMigrationOperationErrorEquality() {
        let error1 = MigrationOperationError.preconditionFailure
        let error2 = MigrationOperationError.unhandledSudoKeyManagerError(cause: SudoKeyManagerError.fatalError)
        let error3 = MigrationOperationError.unhandledSudoKeyManagerError(cause: SudoKeyManagerError.unhandledUnderlyingSecAPIError(code: -1))
        
        XCTAssertEqual(MigrationOperationError.preconditionFailure, error1)
        XCTAssertNotEqual(MigrationOperationError.fatalError, error1)
        XCTAssertEqual(MigrationOperationError.unhandledSudoKeyManagerError(cause: SudoKeyManagerError.fatalError), error2)
        XCTAssertNotEqual(MigrationOperationError.unhandledSudoKeyManagerError(cause: SudoKeyManagerError.keyNotFound), error2)
        XCTAssertEqual(MigrationOperationError.unhandledSudoKeyManagerError(cause: SudoKeyManagerError.unhandledUnderlyingSecAPIError(code: -1)), error3)
        XCTAssertNotEqual(MigrationOperationError.unhandledSudoKeyManagerError(cause: SudoKeyManagerError.unhandledUnderlyingSecAPIError(code: -2)), error3)
    }
    
    func testMigration() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id", isSynchronizable: false, isExportable: false)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            try self.keyManager.generateSymmetricKey("dummy_key_id", isExportable: true)
        } catch let error {
            XCTFail("Failed to generate symmetric key: \(error)")
        }
        
        do {
            try self.keyManager.generateKeyPair("dummy_key_id", isExportable: true)
        } catch let error {
            XCTFail("Failed to generate a key pair: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .symmetricKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Symmetric key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .privateKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Private key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .publicKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Public key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
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
        
        // Migrate all keys.
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.synchronizable, value: .boolValue(true))
            let operation = SimpleMigrationOperation(version: 2, name: "enableSync", description: "Enables sync flag on all keys", keyManager: self.keyManager, searchParams: KeyAttributeSet(), updates: updates)
            try self.migrationManager.addMigrationOperation(operation)
        } catch let error {
            XCTFail("Failed to add migration operation: \(error)")
        }

        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 2, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, let time):
                NSLog("Migration time: %f", time)
                XCTAssertTrue(time > 0.0)
                XCTAssertEqual(2, version)
                XCTAssertEqual(4, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }
        })
        self.waitForCompletionExpectation()
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .symmetricKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Symmetric key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .privateKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Private key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .publicKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Public key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
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
        
        self.migrationManager.reset()
        do {
            var searchParams = KeyAttributeSet()
            searchParams.addAttribute(.type, value: .keyTypeValue(.password))
            var updates = KeyAttributeSet()
            updates.addAttribute(.synchronizable, value: .boolValue(false))
            let operation = SimpleMigrationOperation(version: 2, name: "disableSync", description: "Disables sync flag on all passwords", keyManager: self.keyManager, searchParams: searchParams, updates: updates)
            try self.migrationManager.addMigrationOperation(operation)
        } catch let error {
            XCTFail("Failed to add migration operation: \(error)")
        }
        
        // Check that operations outside the specified version range are not executed.
        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 1, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, let time):
                NSLog("Migration time: %f", time)
                XCTAssertEqual(0.0, time)
                XCTAssertEqual(0, version)
                XCTAssertEqual(0, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }

        })
        self.waitForCompletionExpectation()
        
        // Migrate passwords only.
        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 2, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, _):
                XCTAssertEqual(2, version)
                XCTAssertEqual(1, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }
        })
        self.waitForCompletionExpectation()
        
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
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .symmetricKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Symmetric key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve symmetric key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .privateKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Private key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve private key: \(error)")
        }
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .publicKey) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
            } else {
                XCTFail("Public key not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve public key: \(error)")
        }
    }
    
    func testMigrationUpdateNotNeeded() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id", isSynchronizable: true, isExportable: false)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.synchronizable, value: .boolValue(false))
            let operation = SimpleMigrationOperation(version: 2, name: "disableSync", description: "Disables sync flag on all keys", keyManager: self.keyManager, searchParams: KeyAttributeSet(), updates: updates)
            try self.migrationManager.addMigrationOperation(operation)
        } catch let error {
            XCTFail("Failed to add migration operation: \(error)")
        }
        
        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 2, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, let time):
                NSLog("Migration time: %f", time)
                XCTAssertTrue(time > 0.0)
                XCTAssertEqual(2, version)
                XCTAssertEqual(1, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }
        })
        self.waitForCompletionExpectation()
        
        self.migrationManager.reset()
        
        do {
            var updates = KeyAttributeSet()
            updates.addAttribute(.synchronizable, value: .boolValue(false))
            let operation = SimpleMigrationOperation(version: 2, name: "disableSync", description: "Disables sync flag on all keys", keyManager: self.keyManager, searchParams: KeyAttributeSet(), updates: updates)
            try self.migrationManager.addMigrationOperation(operation)
        } catch let error {
            XCTFail("Failed to add migration operation: \(error)")
        }
        
        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 2, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, let time):
                NSLog("Migration time: %f", time)
                XCTAssertTrue(time > 0.0)
                XCTAssertEqual(2, version)
                XCTAssertEqual(0, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }
        })
        self.waitForCompletionExpectation()
    }
    
    func testMultipleMigrations() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id", isSynchronizable: false, isExportable: true)
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
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), exportable.value)
                } else {
                    XCTFail("Exportable attribute not found.")
                }
            } else {
                XCTFail("Passowrd not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            var synchronizableUpdate = KeyAttributeSet()
            synchronizableUpdate.addAttribute(.synchronizable, value: .boolValue(true))
            try self.migrationManager.addMigrationOperation(SimpleMigrationOperation(version: 1, name: "enableSync", description: "Enables sync flag on all keys", keyManager: self.keyManager, searchParams: KeyAttributeSet(), updates: synchronizableUpdate))
            
            var exportableUpdate = KeyAttributeSet()
            exportableUpdate.addAttribute(.exportable, value: .boolValue(false))
            try self.migrationManager.addMigrationOperation(SimpleMigrationOperation(version: 2, name: "disableExport", description: "Disables export flag on all keys", keyManager: self.keyManager, searchParams: KeyAttributeSet(), updates: exportableUpdate))

        } catch let error {
            XCTFail("Failed to add migration operation: \(error)")
        }
        
        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 2, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, let time):
                NSLog("Migration time: %f", time)
                XCTAssertTrue(time > 0.0)
                XCTAssertEqual(2, version)
                XCTAssertEqual(2, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }
        })
        self.waitForCompletionExpectation()
        
        do {
            if let attributes = try self.keyManager.getKeyAttributes("dummy_key_id", type: .password) {
                if let synchronizable = attributes.getAttribute(.synchronizable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(true), synchronizable.value)
                } else {
                    XCTFail("Synchronizable attribute not found.")
                }
                
                if let exportable = attributes.getAttribute(.exportable) {
                    XCTAssertEqual(KeyAttributeValue.boolValue(false), exportable.value)
                } else {
                    XCTFail("Exportable attribute not found.")
                }
            } else {
                XCTFail("Passowrd not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
    }
    
    func testKeyIdMigration() {
        do {
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id1", isSynchronizable: false, isExportable: false)
            try self.keyManager.addPassword("passw0rd".data(using: String.Encoding.utf8)!, name: "dummy_key_id2", isSynchronizable: false, isExportable: false)
        } catch let error {
            XCTFail("Failed to add password: \(error)")
        }
        
        do {
            var searchParams = KeyAttributeSet()
            searchParams.addAttribute(.id, value: .stringValue("myapp.dummy_key_id1"))
            searchParams.addAttribute(.type, value: .keyTypeValue(.password))
            var updates = KeyAttributeSet()
            updates.addAttribute(.id, value: .stringValue("test.dummy_key_id1"))
            let operation = SimpleMigrationOperation(version: 2, name: "changeKeyId", description: "Changes ID of a key", keyManager: self.keyManager, searchParams: searchParams, updates: updates)
            try self.migrationManager.addMigrationOperation(operation)
        } catch let error {
            XCTFail("Failed to add migration operation: \(error)")
        }
        
        self.createCompletionExpectation()
        self.migrationManager.migrate(0, to: 2, completion: { (result) in
            defer {
                self.fulfillCompletionExpectation()
            }
            switch result {
            case .success(let version, let count, let time):
                NSLog("Migration time: %f", time)
                XCTAssertTrue(time > 0.0)
                XCTAssertEqual(2, version)
                XCTAssertEqual(1, count)
            case .failure(let errors, let version, let count):
                XCTFail("Failed to perform the migration: version=\(version), count=\(count), errors=\(errors)")
            }
        })
        self.waitForCompletionExpectation()
        
        XCTAssertNil(try self.keyManager.getPassword("dummy_key_id1"))
        
        do {
            if let password = try self.keyManagerTestNamespace.getPassword("dummy_key_id1") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
        
        do {
            if let password = try self.keyManager.getPassword("dummy_key_id2") {
                XCTAssertEqual("passw0rd", String(data: password, encoding: String.Encoding.utf8))
            } else {
                XCTFail("Password not found.")
            }
        } catch let error {
            XCTFail("Failed to retrieve password: \(error)")
        }
    }

}

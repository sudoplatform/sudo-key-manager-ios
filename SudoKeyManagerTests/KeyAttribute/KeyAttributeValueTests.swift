//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
@testable import SudoKeyManager

class KeyAttributeValueTests: XCTestCase {

    // MARK: - Tests: Hashable

    func testHashValueMatchesForEachCase() {
        let stringValue = KeyAttributeValue.stringValue("STRING")
        XCTAssertEqual(KeyAttributeValue.stringValue("STRING").hashValue, stringValue.hashValue)

        let boolValue = KeyAttributeValue.boolValue(true)
        XCTAssertEqual(KeyAttributeValue.boolValue(true).hashValue, boolValue.hashValue)

        let intValue = KeyAttributeValue.intValue(1)
        XCTAssertEqual(KeyAttributeValue.intValue(1).hashValue, intValue.hashValue)

        let dataValue = KeyAttributeValue.dataValue(Data())
        XCTAssertEqual(KeyAttributeValue.dataValue(Data()).hashValue, dataValue.hashValue)

        let keyTypeValue = KeyAttributeValue.keyTypeValue(.password)
        XCTAssertEqual(KeyAttributeValue.keyTypeValue(.password).hashValue, keyTypeValue.hashValue)
    }

    // MARK: - Tests: Equatable

    func testEquatabilityForEachCase() {
        let stringValue = KeyAttributeValue.stringValue("STRING")
        XCTAssertEqual(.stringValue("STRING"), stringValue)
        XCTAssertNotEqual(.stringValue("DIFFERENT_STRING"), stringValue)

        let boolValue = KeyAttributeValue.boolValue(true)
        XCTAssertEqual(.boolValue(true), boolValue)
        XCTAssertNotEqual(.boolValue(false), boolValue)

        let intValue = KeyAttributeValue.intValue(1)
        XCTAssertEqual(.intValue(1), intValue)
        XCTAssertNotEqual(.intValue(2), intValue)

        let dataValue = KeyAttributeValue.dataValue(Data())
        XCTAssertEqual(.dataValue(Data()), dataValue)
        XCTAssertNotEqual(.dataValue(Data(count: 10)), dataValue)

        let keyTypeValue = KeyAttributeValue.keyTypeValue(.password)
        XCTAssertEqual(.keyTypeValue(.password), keyTypeValue)
        XCTAssertNotEqual(.keyTypeValue(.privateKey), keyTypeValue)
    }

}

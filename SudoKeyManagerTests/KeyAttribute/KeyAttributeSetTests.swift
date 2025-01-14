//
// Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
@testable import SudoKeyManager

class KeyAttributeSetTests: XCTestCase {

    // MARK: - Properties

    let dummyAttribute = KeyAttribute(name: .name, value: .stringValue("dummy_value"))

    // MARK: - Helpers

    /// Creates a populated test object with data. Uses dummy data if nil is supplied.
    func createPopulatedSet(attributes: Set<KeyAttribute>? = nil) -> KeyAttributeSet {
        let attributes = attributes ?? Set<KeyAttribute>(arrayLiteral: dummyAttribute)
        return KeyAttributeSet(attributes: attributes)
    }

    // MARK: - Tests: Supplementary

    func testMutableAttributes() {
        XCTAssertEqual([.synchronizable, .exportable, .id], KeyAttributeSet.MutableAttributes)
    }

    func testSearchAttributes() {
        XCTAssertEqual([.id, .type, .synchronizable, .exportable], KeyAttributeSet.SearchAttributes)
    }

    // MARK: - Tests: Constructors

    func testEmptyInitializer() {
        let set = KeyAttributeSet()
        XCTAssertEqual(0, set.count)
    }

    func testInternalTypeInitializer() {
        var set = Set<KeyAttribute>()
        set.insert(dummyAttribute)

        let setObject = KeyAttributeSet(attributes: set)
        XCTAssertEqual(dummyAttribute, setObject.attributes.first)
        XCTAssertEqual(1, setObject.count)
    }

    // MARK: - Tests: Data Manipulation

    func testAddAttribute() {
        var set = KeyAttributeSet()

        set.addAttribute(.name, value: .stringValue("dummy_value"))
        XCTAssertEqual(1, set.count)
        XCTAssertEqual(dummyAttribute, set.attributes.first)
    }

    func testRemoveAttribute() {
        var set = createPopulatedSet()

        XCTAssertEqual(1, set.count)
        set.removeAttribute(.name)
        XCTAssertEqual(0, set.count)
    }

    // MARK: - Tests: Data Access

    func testGetAttribute() {
        let set = createPopulatedSet()

        XCTAssertEqual(dummyAttribute, set.getAttribute(.name))
        XCTAssertNil(set.getAttribute(.id))
    }

    func testIsSubsetOf() {
        let nameSet = createPopulatedSet()

        let nameAndIdSet = createPopulatedSet(attributes: .init([
            dummyAttribute,
            .init(name: .id, value: .stringValue("dummy_id"))
        ]))

        XCTAssertTrue(nameSet.isSubsetOf(nameAndIdSet))
    }

    func testIsNotSubsetOf() {
        let nameSet = createPopulatedSet()

        let differentNameAndIdSet = createPopulatedSet(attributes: .init([
            .init(name: .name, value: .stringValue("DIFFERENT")),
            .init(name: .id, value: .stringValue("dummy_id"))
            ]))

        XCTAssertFalse(nameSet.isSubsetOf(differentNameAndIdSet))
    }

    func testSubtractingSameSubtracts() {
        let set = createPopulatedSet()

        let subtractedSet = set.subtracting(.init(attributes: .init([dummyAttribute])))
        XCTAssertEqual(0, subtractedSet.count)
    }

    func testSubtractingDifferenceDoesNotSubtract() {
        let set = createPopulatedSet()

        let noSubtractSet = set.subtracting(.init(attributes: .init([.init(name: .name, value: .stringValue("DIFF"))])))
        XCTAssertEqual(1, noSubtractSet.count)
    }

    func testIsSearchableNotSearchable() {
        let notSearchableAttributeNames: [KeyAttributeName] = [.data, .name, .namespace, .version]
        for name in notSearchableAttributeNames {
            let set = KeyAttributeSet(attributes: .init([.init(name: name, value: .stringValue("dummy_value"))]))
            XCTAssertFalse(set.isSearchable())
        }
    }

    func testIsSearchable() {
        let searchableAttributeNames: [KeyAttributeName] = [.id, .type, .synchronizable, .exportable]
        for name in searchableAttributeNames {
            let set = KeyAttributeSet(attributes: .init([.init(name: name, value: .stringValue("dummy_value"))]))
            XCTAssertTrue(set.isSearchable())
        }
    }

    func testIsMutable() {
        let mutableAttributeNames: [KeyAttributeName] =  [.synchronizable, .exportable, .id]
        for name in mutableAttributeNames {
            let set = KeyAttributeSet(attributes: .init([.init(name: name, value: .stringValue("dummy_value"))]))
            XCTAssertTrue(set.isMutable())
        }
    }

    func testIsMutableNotMutable() {
        let mutableAttributeNames: [KeyAttributeName] =  [.data, .name, .namespace, .type, .version]
        for name in mutableAttributeNames {
            let set = KeyAttributeSet(attributes: .init([.init(name: name, value: .stringValue("dummy_value"))]))
            XCTAssertFalse(set.isMutable())
        }
    }

    // MARK: - Tests: Equatable

    func testEquality() {
        let set = createPopulatedSet()
        var set2 = createPopulatedSet()

        XCTAssertEqual(set, set2)

        set2.addAttribute(.data, value: .boolValue(true))
        XCTAssertNotEqual(set2, set)
    }

}

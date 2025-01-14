//
// Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
@testable import SudoKeyManager

class ASN1Tests: XCTestCase {
 
    func testUInt8ToBits() {
        let zero: UInt8 = 0x00
        let five: UInt8 = 0x05
        let twoFiftyFive: UInt8 = 0xFF
        
        XCTAssertEqual([.zero, .zero, .zero, .zero, .zero, .zero, .zero, .zero], zero.bits())
        XCTAssertEqual([.zero, .zero, .zero, .zero, .zero, .one, .zero, .one], five.bits())
        XCTAssertEqual([.one, .one, .one, .one, .one, .one, .one, .one], twoFiftyFive.bits())
    }
    
    func testAsn1EncodedLength() {
        let five: Int = 5
        let twoFiftyEight: Int = 258

        let fiveEncoded = five.asn1EncodedLength()
        XCTAssertEqual(1, fiveEncoded.count)
        XCTAssertEqual([.zero, .zero, .zero, .zero, .zero, .one, .zero, .one], fiveEncoded[0].bits())
        
        let twoFiftyEightEncoded = twoFiftyEight.asn1EncodedLength()
        XCTAssertEqual(3, twoFiftyEightEncoded.count)
        XCTAssertEqual([.one, .zero, .zero, .zero, .zero, .zero, .one, .zero], twoFiftyEightEncoded[0].bits())
        XCTAssertEqual([.zero, .zero, .zero, .zero, .zero, .zero, .zero, .one], twoFiftyEightEncoded[1].bits())
        XCTAssertEqual([.zero, .zero, .zero, .zero, .zero, .zero, .one, .zero], twoFiftyEightEncoded[2].bits())
    }
    
}

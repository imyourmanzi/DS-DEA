//
//  File.swift
//  
//
//  Created by Matt Manzi on 2/26/20.
//

import XCTest
import class Foundation.Bundle
//@testable import SDES

final class SDESTests: XCTestCase {
    
    static var allTests = [
//        ("testRotatedLeft", testRotatedLeft),
        ("testSubstitute", testSubstitute)
    ]
    
    private var sdes: SDESCore!
    
    override func setUp() {
        super.setUp()
        sdes = SDESCore()
    }
    
    func testRotatedLeft() throws {
//        let number: UInt16 = 0xFFFF
//        let rotated = number.rotatedLeft(by: 1)
//
//        XCTAssertEqual(rotated, 0xFFFF)
    }

    func testSubstitute() throws {

    }
    
}

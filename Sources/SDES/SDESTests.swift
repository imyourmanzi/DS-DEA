//
//  SDESTests.swift
//  Poor-boi's testing here because Swift's unit test machine BROKE.
//
//  Created by Matt Manzi on 2/27/20.
//  Project 2 of CMSC 487, Spring 2020.
//

import Foundation

public class SDESTests {

    private var core: SDESCore!
    
    public func runTests() {
        setUp()
//        testRotatedLeft()
        varibalePlaintextKnownAnswerTest()
        tearDown()
    }

    func setUp() {
        core = SDESCore()
    }
    
    func tearDown() {
        core = nil
    }
    
    func testRotatedLeft() {
        var original: UInt16 = 0b0000000000011111
        var rotated = original.rotatedLeft(by: 16, forBitsUpTo: 18)
        print("testRotatedLeft 0b11111 by 16 for 18: \(rotated == original)")
        
        original = 0b0000000000011110
        rotated = original.rotatedLeft(by: 3, forBitsUpTo: 5)
        print("testRotatedLeft 0b11110 by 3 for 5: \(rotated == 0b0000000000010111)")
        
        original = 0b0000000000000000
        rotated = original.rotatedLeft(by: 3, forBitsUpTo: 5)
        print("testRotatedLeft 0 by 3 for 5: \(rotated == 0b0000000000000000)")
    }
    
    func varibalePlaintextKnownAnswerTest() {
        let answers = [
            0b10101000,
            0b10111110,
            0b00010110,
            0b01001010,
            0b01001001,
            0b01001110,
            0b00010101,
            0b01101000
        ]
        
        let key: UInt16 = 0b0000000000000000
        var p: UInt8 = 0b10000000
        
        for i in 1...8 {
            let out = core.encrypt(p, with: key)
            print("varibalePlaintextKnownAnswerTest \(i): \(out == answers[i - 1])")
            p = p >> 1
        }
        
    }

}

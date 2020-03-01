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
    
    
    // MARK: - Tester Methods
    
    public func runTests() {
        setUp()
        testRotatedLeft()
        testPermute()
        varibalePlaintextKnownAnswerTest()
        inversePermutationKnownAnswerTest()
        variableKeyKnownAnswerTest()
        permutationOperationKnownAnswerTest()
        substitutionTableKnownAnswerTest()
        tearDown()
    }

    func setUp() {
        core = SDESCore()
    }
    
    func tearDown() {
        core = nil
    }
    
    
    // MARK: - Utility Tests
    
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
    
    func testPermute() {
        var original: UInt8 = 0b10011010
        var permutation: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        var permuted = core.permute(original, by: permutation)
        var answer = original
        print("testPermute 0b\(String(original, radix: 2)) == 0b\(String(permuted, radix: 2)): \(permuted == answer)")
        
        original = 0b10011010
        permutation = [1, 4, 5, 7, 2, 3, 6, 8]
        permuted = core.permute(original, by: permutation)
        answer = 0b11110000
        print("testPermute 0b\(String(original, radix: 2)) => 0b\(String(permuted, radix: 2)) == 0b\(String(answer, radix: 2)): \(permuted == answer)")
        
        original = 0b00000010
        permutation = [2, 3, 1]
        permuted = core.permute(original, by: permutation)
        answer = 0b00000100
        print("testPermute 0b\(String(original, radix: 2)) => 0b\(String(permuted, radix: 2)) == 0b\(String(answer, radix: 2)): \(permuted == answer)")
        
        original = 0b00001001
        permutation = [4, 1, 2, 3, 2, 3, 4, 1]
        permuted = core.permute(original << 4, by: permutation)
        answer = 0b11000011
        print("testPermute 0b\(String(original, radix: 2)) => 0b\(String(permuted, radix: 2)) == 0b\(String(answer, radix: 2)): \(permuted == answer)")
    }
    
    
    // MARK: - Encryption Tests
    
    func varibalePlaintextKnownAnswerTest() {
        let answers: [UInt8] = [
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
        // for basis vectors
        var p: UInt8 = 0b10000000
        
        for i in 0..<answers.count {
            let out = core.encrypt(p, with: key)
            print("varibalePlaintextKnownAnswerTest \(i): \(out == answers[i])")
            p = p >> 1
        }
        
    }
    
    func inversePermutationKnownAnswerTest() {
        var answer: UInt8 = 0b10000000
        let key: UInt16 = 0b0000000000000000
        let p: [UInt8] = [
            0b10101000,
            0b10111110,
            0b00010110,
            0b01001010,
            0b01001001,
            0b01001110,
            0b00010101,
            0b01101000
        ]
        
        for i in 0..<p.count {
            let out = core.encrypt(p[i], with: key)
            print("inversePermutationKnownAnswerTest \(i): \(out == answer)")
            answer = answer >> 1
        }
    }
    
    func variableKeyKnownAnswerTest() {
        let answers: [UInt8] = [
            0b01100001,
            0b00010011,
            0b01001111,
            0b11100101,
            0b01100101,
            0b01011100,
            0b10101110,
            0b11011001,
            0b10101010,
            0b01001110
        ]
        var key: UInt16 = 0b0000001000000000
        let p: UInt8 = 0b00000000
        
        for i in 0..<answers.count {
            let out = core.encrypt(p, with: key)
            print("variableKeyKnownAnswerTest \(i): \(out == answers[i])")
            key = key >> 1
        }
        
    }

    func permutationOperationKnownAnswerTest() {
        let answers: [UInt8] = [
            0b00000011,
            0b00100010,
            0b01000000,
            0b01100000
        ]
        let keys: [UInt16] = [
            0b0000000011,
            0b0011001010,
            0b0001011001,
            0b1011001111
        ]
        let p: UInt8 = 0b00000000
        
        for i in 0..<answers.count {
            let out = core.encrypt(p, with: keys[i])
            print("permutationOperationKnownAnswerTest \(i): \(out == answers[i])")
        }
        
    }
    
    func substitutionTableKnownAnswerTest() {
        let answers: [UInt8] = [
            0b10000111,
            0b10110110,
            0b10110100,
            0b00110011,
            0b11011001,
            0b10001101,
            0b00010001
        ]
        let keys: [UInt16] = [
            0b0001101101,
            0b0001101110,
            0b0001110000,
            0b0001110001,
            0b0001110110,
            0b0001111000,
            0b0001111001
        ]
        let p: UInt8 = 0b00000000
        
        for i in 0..<answers.count {
            let out = core.encrypt(p, with: keys[i])
            print("substitutionTableKnownAnswerTest \(i): \(out == answers[i])")
        }
        
    }
    
    
    // MARK: - Decryption Tests
    
    func variableCiphertextKnownAnswerTest() {
        
    }
    
    func initialPermutationKnownAnswerTest() {
        
    }
    
    func variableKeyKnownAnswerTestDecryption() {
        
    }
    
    func permutationOperationKnownAnswerTestDecryption() {
        
    }
    
    func substitutionTableKnownAnswerTestDecryption() {
        
    }
    
}

//
//  s_des.swift
//  Houses all the core functionality of the Simplified Data Encryption Standard
//  (S-DES).
//
//  Created by Matt Manzi on 2/25/20.
//  Project 2 of CMSC 487, Spring 2020.
//

import Foundation

/// The total number of rounds for ciphering.
let ROUNDS = 4

/// The initial and inverse initial permuation vectors, respectively.
let IP: [[UInt8]] = [
    [2, 6, 3, 1, 4, 8, 5, 7],
    [4, 1, 3, 5, 7, 2, 8, 6]
]

/// The mask to zero out non-key bits.
let KEY_MASK: UInt16 = 0b0000001111111111

/// The permuted choice vectors PC1 and PC2 for key schedule, respectively.
let PC: [[UInt16]] = [
    [3, 5, 2, 7, 4, 10, 1, 9, 8, 6],
    [6, 3, 7, 4, 8, 5, 10, 9]
]

/// The number of left shifts (rotations) to perform for the respective round of the key schedule.
let ROTATIONS = [1, 2, 2, 2]

/// The selections of the R-bits in f.
let E: [UInt8] = [4, 1, 2, 3, 2, 3, 4, 1]

/// The substitution boxes S1 and S2, respectively.
let S: [[[UInt8]]] = [
    [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ],
    [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]
]

/// The permutation vector P for f.
let P: [UInt8] = [2, 4, 3, 1]

/**
 Enciphers an 8-bit block using a key schedule array of keys.  Note that this function also deciphers enciphered blocks when given the ciphertext and the same, but reversed, key schedule array.
 
 - Parameter block: The 8-bit block to encipher.
 - Parameter keys: An array of cipher keys.
 
 - Precondition: This function expects `keys` was  generated with the `scheduleKeys()` function.
 
 - Returns: The 8-bit, enciphered permutation of `block`.
 */
func cipher(_ block: UInt8, using keys: [UInt8]) -> UInt8 {
    
    // initial permutation
    let permuted = permute(block, by: IP[0])
    
    /*
     split block into L and R, like:
         MSb                   LSb
         +-----------+-----------+
         |     r     |     l     |
         +-----------+-----------+
     */
    var l: UInt8 = (permuted & 0x0F)
    var r: UInt8 = (permuted & 0xF0) >> 4
    
    // perform cipherment rounds
    for i in 0..<ROUNDS {
        let temp = l ^ f(r, keys[i])
        l = r
        r = temp
    }
    
    /*
     combine L and R into single block, like:
         MSb                   LSb
         +-----------+-----------+
         |     l     |     r     |
         +-----------+-----------+
     */
    let preoutput: UInt8 = (l << 4) | r
    
    // inverse initial permutation
    let output = permute(preoutput, by: IP[1])
    
    return output
}

/**
 Permutes (rearranges) bits of `UnsignedInteger` types through the use of a permutation vector.
 
 - Parameter bits: The bits to be permuted.
 - Parameter vector: The permutation vector that describes how to permute the bits.
 
 - Precondition: `vector` must not contain more elements than `bits.bitWidth`.  It describes the ordering of each bit where the first element indicates which bit will be placed in the position of least significant bit (LSb), the second bit number is the bit number to be moved into the second-LSb position, and so on.  Bits are numbered `1...bits.bitWidth`.
 
 - Returns: The bits of `bits` in the permuted order.
 */
func permute<T: UnsignedInteger>(_ bits: T, by vector: [T]) -> T {
    
    // isolate each bit and move it to it's permutated position
    var permuted: T = 0
    for (i, bit) in vector.enumerated() {
        
        // find the bit to mask and the amount to shift
        let mask: T = 1 << (bit - 1)
        let shift = (i + 1) - Int(bit)
        
        // add it to the rest of the bits
        permuted |= (bits & mask) << shift
        
    }
    
    return permuted
}

/**
 Generates the schedule of keys to use with enciphering a block.
 
 - Parameter key: The 10-bit key which will be used to generate the schedule of keys.
 
 - Precondition: The expected `key` will have 16 bits, however the most significant 6 bits will be ignored.
 
 - Returns: The schedule of keys: an array of four 8-bit keys.
 */
func scheduleKeys(from key: UInt16) -> [UInt8] {
    
    // calculate permuted choice 1, first masking out the upper 6 bits
    let pc1 = permute(key & KEY_MASK, by: PC[0])
    
    /*
    split into C and D, like:
        MSb                   LSb
        +-----------+-----------+
        |     d     |     c     |
        +-----------+-----------+
    */
    var c: UInt16 = (pc1 & 0b0000000000011111)
    var d: UInt16 = (pc1 & 0b0000001111100000) >> 5
    var keys: [UInt8] = []
    
    // for each round, do the corresponding number of rotate left operations
    for i in 0..<ROUNDS {
        
        // rotate left for current round
        c = c.rotatedLeft(by: ROTATIONS[i]) & 0b0000000000011111
        d = d.rotatedLeft(by: ROTATIONS[i]) & 0b0000000000011111
        
        // combine the key and add it to the array of keys in the schedule
        let temp = permute((d << 5) | c, by: PC[1])
        keys.append(UInt8(truncatingIfNeeded: temp))
        
    }
    
    return keys
}

/**
 Performs the core ciphering function of S-DES.
 
 - Parameter r: The (right-half) block of four bits.
 - Parameter key: The key to encipher with.
 
 - Precondition: The expected `r` will have 8 bits, however the most significant 4 bits will be ignored.
 
 - Returns: The enciphered block of four bits.
 
 - Postcondition: The return value will have 8 bits, however only the least significant 4 bits will used.
 */
func f(_ r: UInt8, _ key: UInt8) -> UInt8 {
    
    // expand R bits using E vector, XOR w/ key, after masking out upper 4 bits
    let expanded = permute(r & 0x0F, by: E) ^ key
    
    // split into two halves (b1 is least significant nibble)
    let b1 = (expanded & 0x0F)
    let b2 = (expanded & 0xF0) >> 4
    
    // get substitutions
    let s1 = substitute(nibble: b1, using: S[0])
    let s2 = substitute(nibble: b2, using: S[1])
    
    // combine the substitution results (s2 becomes most significant 2 bits)
    let permuted: UInt8 = permute((s2 << 2) | s1, by: P) & 0x0F
    
    return permuted
}

/**
 Substitutes four bits for a corresponding combination of two bits based on a substitution box.
 
 - Parameter nibble: The four bits to input to the substitution box.
 - Parameter box: The substitution box to use.
 
 - Precondition: The expected `nibble` will have 8 bits, however the most significant 4 bits will be ignored.
 
 - Returns: The 2-bit result of the substitution.
 
 - Postcondition: The return value will have 8 bits, however only the least significant 2 bits will used.
 */
func substitute(nibble: UInt8, using box: [[UInt8]]) -> UInt8 {
    
    // determine col and row of box
    let i: UInt8 = ((nibble & 0b00001000) >> 2) | (nibble & 0b00000001)
    let j: UInt8 = (nibble & 0b00000110) >> 1
    
    return (box[Int(i)][Int(j)] & 0x03)
}

extension UInt16 {
    
    /**
     Circularly rotates bits of the number left by a desired amount.
     
     - Parameter places: The number of single left-rotations to perform.
     
     - Returns: The original number after its rotation.
     */
    func rotatedLeft(by places: Int) -> UInt16 {
        return (self << places) | (self >> (self.bitWidth - places))
    }
    
}

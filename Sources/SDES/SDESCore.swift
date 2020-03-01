//
//  SDES.swift
//  Houses all the core functionality of the Simplified Data Encryption Standard
//  (S-DES).
//
//  Created by Matt Manzi on 2/25/20.
//  Project 2 of CMSC 487, Spring 2020.
//

import Foundation


// MARK: - Constants

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


// MARK: - SDES Core Functionality

/// An implementation of the S-DES algorithm for single blocks of 8-bits.
public class SDESCore {
    
    /**
     Encrypts an 8-bit block of data using the provided key.
     
     - Parameter block: The block to encrypt.
     - Parameter key: The key to encrypt the block with.
     
     - Returns: The `key`-encrypted version of `block`.
     */
    public func encrypt(_ block: UInt8, with key: UInt16) -> UInt8 {
        
        // generate schedule of keys
        let keySchedule = scheduleKeys(from: key)
        
        // encipher the block
        let ciphertext = cipher(block, using: keySchedule)
        
        return ciphertext
    }
    
    /**
    Decrypts an 8-bit block of data using the provided key.
    
    - Parameter block: The block to decrypt.
    - Parameter key: The key to decrypt the block with.
    
    - Returns: The `key`-decrypted version of `block`.
    */
    public func decrypt(_ block: UInt8, with key: UInt16) -> UInt8 {
        
        // generate schedule of keys
        let reversedKeySchedule: [UInt8] = scheduleKeys(from: key).reversed()
        
        // decipher the block
        let plaintext = cipher(block, using: reversedKeySchedule)
        
        return plaintext
    }
    
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
         |     l     |     r     |
         +-----------+-----------+
         */
        var r: UInt8 = (permuted & 0x0F)
        var l: UInt8 = (permuted & 0xF0) >> 4
        
        // perform cipherment rounds
        var temp: UInt8 = 0
        for i in 0..<ROUNDS {
            temp = l ^ f(r, keys[i])
            l = r
            r = temp
        }
        
        /*
         combine L and R into single block, like:
         MSb                   LSb
         +-----------+-----------+
         |     r     |     l     |
         +-----------+-----------+
         */
        let preoutput: UInt8 = (r << 4) | l
        
        // inverse initial permutation
        let output = permute(preoutput, by: IP[1])
        
        return output
    }
    
    /**
     Permutes (rearranges) bits of `UnsignedInteger` types through the use of a permutation vector.
     
     - Parameter bits: The bits to be permuted.
     - Parameter vector: The permutation vector that describes how to permute the bits.
     - Parameter sigBits: The number of bits that are significant in the input `bits`.
     
     - Precondition: `vector` must not contain more elements than `bits.bitWidth`.  It describes the ordering of each bit where the first element indicates which bit will be placed in the position of most significant bit (MSb), the second bit number is the bit number to be moved into the second-MSb position, and so on.  Bits are numbered `1...bits.bitWidth`.
     - Postcondition: The effective bit width of the return value will be equivalent to `vector.count`.
     
     - Returns: The bits of `bits` in the permuted order.
     */
    func permute<T>(_ bits: T, by vector: [T],
                    usingBits sigBits: Int = -1) -> T where T: UnsignedInteger {
        
        var significantBits = sigBits
        if sigBits < 0 {
            significantBits = vector.count
        }
            
        // shift the bits so that 1 is in the MSb position of T
        let workingBits = bits << (bits.bitWidth - significantBits)
        
        // isolate each bit and move it to it's permutated position
        var permuted: T = 0
        for (i, bit) in vector.enumerated() {
            
            // find the bit to mask and the amount to shift
            let mask: T = 1 << (workingBits.bitWidth - Int(bit))
            let shift = Int(bit) - (i + 1)
            
            // add it to the rest of the bits
            permuted |= (workingBits & mask) << shift
            
        }
        
        // move to right in case we're not filling the whole bitWidth
        return permuted >> (workingBits.bitWidth - vector.count)
    }
    
    /**
     Generates the schedule of keys to use with enciphering a block.
     
     - Parameter key: The 10-bit key which will be used to generate the schedule of keys.
     
     - Precondition: The expected `key` will have 16 bits, however the most significant 6 bits will be ignored.
     
     - Returns: The schedule of keys: an array of four 8-bit keys.
     */
    func scheduleKeys(from key: UInt16) -> [UInt8] {
        
        // calculate permuted choice 1, anded with key mask
        let pc1 = permute(key & KEY_MASK, by: PC[0])
        
        /*
         split into C and D, like:
         MSb                   LSb
         +-----------+-----------+
         |     c     |     d     |
         +-----------+-----------+
         */
        var c: UInt16 = (pc1 & 0b0000001111100000) >> 5
        var d: UInt16 = (pc1 & 0b0000000000011111)
        var keys: [UInt8] = []
        
        // for each round, do the corresponding number of rotate left operations
        for i in 0..<ROUNDS {
            
            // rotate left for current round
            c = c.rotatedLeft(by: ROTATIONS[i], forBitsUpTo: 5)
            d = d.rotatedLeft(by: ROTATIONS[i], forBitsUpTo: 5)
            
            // combine the key and add it to the array of keys in the schedule
            let combined: UInt16 = (c << 5) | d
            let permuted: UInt16 = permute(combined, by: PC[1], usingBits: 10)
            let trunked: UInt8 = UInt8(truncatingIfNeeded: permuted)
            keys.append(trunked)
            
        }
        
        return keys
    }
    
    /**
     Performs the core ciphering function of S-DES.
     
     - Parameter r: The (right-half) block of four bits.
     - Parameter key: The key to encipher with.
     
     - Precondition: The expected `r` will have 8 bits, however the most significant 4 bits will be ignored.
     - Postcondition: The return value will have 8 bits, however only the least significant 4 bits will used.
     
     - Returns: The enciphered block of four bits.
     */
    func f(_ r: UInt8, _ key: UInt8) -> UInt8 {
        
        // expand nibble of R bits using E vector, then XOR with key
        let expanded = permute(r << 4, by: E) ^ key
        
        // split into two halves (b1 is most significant nibble)
        let b1 = (expanded & 0xF0) >> 4
        let b2 = (expanded & 0x0F)
        
        // get substitutions
        let s1 = substitute(nibble: b1, using: S[0])
        let s2 = substitute(nibble: b2, using: S[1])
        
        // combine the substitution results (s2 becomes most significant 2 bits)
        let permuted = permute((s1 << 2) | s2, by: P) & 0x0F
        
        return permuted
    }
    
    /**
     Substitutes four bits for a corresponding combination of two bits based on a substitution box.
     
     - Parameter nibble: The four bits to input to the substitution box.
     - Parameter box: The substitution box to use.
     
     - Precondition: The expected `nibble` will have 8 bits, however the most significant 4 bits will be ignored.
     - Postcondition: The return value will have 8 bits, however only the least significant 2 bits will used.
     
     - Returns: The 2-bit result of the substitution.
     */
    func substitute(nibble: UInt8, using box: [[UInt8]]) -> UInt8 {
        
        // determine col and row of box
        let i: UInt8 = ((nibble & 0b00001000) >> 2) | (nibble & 0b00000001)
        let j: UInt8 = (nibble & 0b00000110) >> 1
        
        return (box[Int(i)][Int(j)] & 0b00000011)
    }
    
}


// MARK: - Class & Protocol Extensions

extension UInt16 {
    
    /**
     Circularly rotates bits of the number left by a desired amount.
     
     - Parameter shift: The number of single left-rotations to perform.
     - Parameter maxPlace: The number of bits (starting from the least significant bit) to rotate.  This number can only be as large as the `bitWidth` of the number.  For example, `3` would rotate the subset of bits representing 1, 2, and 4.
     
     - Precondition: Providing `maxPlaces` with a value larger than the `bitWidth` will be ignored and rotate all of the bits.
     
     - Returns: The original number after its rotation.
     */
    public func rotatedLeft(by shift: Int,
                            forBitsUpTo maxPlace: Int = 16) -> UInt16 {
        
        // simple rotates using the whole 2 bytes
        if maxPlace >= self.bitWidth {
            return (self << shift) | (self >> (self.bitWidth - shift))
        }
        
        // when rotating a subset of bits
        let endMask = UInt16.max >> (self.bitWidth - maxPlace)
        let dirtyRotate = (self << shift) | (self >> (maxPlace - shift))
        return dirtyRotate & endMask
    }
    
}

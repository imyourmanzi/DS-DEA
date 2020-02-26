//
//  s_des.swift
//  Houses all the core functionality of the Simplified Data Encryption Standard (DES).
//
//  Created by Matt Manzi on 2/25/20.
//  Project 2 of CMSC 487, Spring 2020.
//

import Foundation

let ROUNDS = 4
let IP: [[UInt8]] = [
    [2, 6, 3, 1, 4, 8, 5, 7],
    [4, 1, 3, 5, 7, 2, 8, 6]
]

/**
 TODO: comment
 */
func cipher(_ block: UInt8, using key: UInt16) -> UInt8 {
    
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
        
        let k = ks(i + 1, key)
        
        let temp = l ^ f(r, k)
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
    let preoutput: UInt8 = (l << 4) + r
    
    // inverse initial permutation
    let output = permute(preoutput, by: IP[1])
    
    return output
}

/**
 TODO: comment
 */
func permute<T: UnsignedInteger>(_ bits: T, by vector: [T]) -> T {
    
    // isolate each bit and move it to it's permutated position
    var permuted: T = 0
    for (i, bit) in vector.enumerated() {
        let mask: T = 1 << (bit - 1)
        let shift = (i + 1) - Int(bit)
        permuted += (bits & mask) << shift
    }
    
    return permuted
}

/**
 TODO: implement
 */
func ks(_ round: Int, _ key: UInt16) -> UInt8 {
    
    return 0
}

/**
 TODO: implement
 */
func f(_ halfBlock: UInt8, _ k: UInt8) -> UInt8 {
    
    return 0
}

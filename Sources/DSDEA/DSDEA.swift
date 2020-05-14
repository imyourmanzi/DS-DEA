//
//  DSDEA.swift
//  Houses the complete implementation of the Double Simplified Data Encryption
//  Algorithm (DS-DEA).
//
//  Created by Matt Manzi on 3/1/20.
//

import Foundation

/// The initialization vector to use for CBC mode.
let IV: UInt8 = 0x9c

/// The user-facing portion of DS-DEA which uses double S-DES in CBC mode.
public class DSDEA {

    /// An instance of the core SDES functionality class.
    private static let core = SDESCore()

    /**
    Encrypts a data array using the provided keys, based on the DS-DEA specification in CBC mode.

    - Postcondition: The returned array will be the same size as the original.

    - Parameter data: The data to encrypt.
    - Parameter keys: The two keys to encrypt the data with.

    - Returns: The `keys`-encrypted data.
    */
    public static func encrypt(_ data: [UInt8],
                               with keys: [UInt16]) -> [UInt8] {
        var c: UInt8 = IV
        var out: [UInt8] = []

        // double-encrypt each block
        for i in data {
            c = core.encrypt(core.encrypt(i ^ c, with: keys[0]), with: keys[1])
            out.append(c)
        }

        return out
    }

    /**
     Decrypts a data array using the provided keys, based on the DS-DEA specification in CBC mode.

     - Postcondition: The returned array will be the same size as the original.

     - Parameter data: The data to decrypt.
     - Parameter keys: The two keys to decrypt the data with.

     - Returns: The `keys`-decrypted data.
     */
    public static func decrypt(_ data: [UInt8],
                               with keys: [UInt16]) -> [UInt8] {
        var c: UInt8 = IV
        var p: UInt8 = 0x00
        var out: [UInt8] = []

        // double-decrypt each block
        for i in data {
            p = core.decrypt(core.decrypt(i, with: keys[1]), with: keys[0]) ^ c
            out.append(p)

            // keep the current ciphertext for the XOR for the next decryption
            c = i
        }

        return out
    }

}

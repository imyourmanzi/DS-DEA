//
//  SDESTests.swift
//  Poor-boi's testing here because Swift's unit test machine BROKE.
//
//  Created by Matt Manzi on 2/27/20.
//  Project 2 of CMSC 487, Spring 2020.
//

import Foundation

/// A set of tests to verify the encrypt and decrypt operations of the (D)S-DES implementation.
final class SDESTests {

    /// An instance of the core SDES functionality class.
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
    
    /**
     Verify encryption with respect to IP and E.
     
     To perform the Variable Plaintext Known Answer Test, the test supplies the IUT with initial values for the key, the plaintext(s) and, if applicable, the initialization vector(s). The test initializes all keys to zero. Each block of data input into the S-DEA is represented as a 8-bit basis vector.

     This test is repeated 8 times, using the 8 input basis vectors, allowing for every possible basis vector to be tested. At the completion of the 8th cycle, all results are verified for correctness.

     If correct results are obtained from an IUT, the Variable Plaintext Known Answer Test has verified the initial permutation IP and the expansion matrix E via the encrypt operation by presenting a full set of basis vectors to IP and to E. The test also verifies the inverse permutation IP-1 via the decrypt operation. It does this by presenting the recovered basis vectors to IP-1.
     */
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
    
    /**
     Verify encryption with respect to IP-1.
     
     To perform the Inverse Permutation Known Answer Test, the test supplies the IUT with initial values for the key, the plaintext(s) and, if applicable, the initialization vector(s).

     This test performs the same processing as the Variable Plaintext Known Answer Test. The difference is that the plaintext value(s) for this test are set to the ciphertext result(s) obtained from the Variable Plaintext Known Answer Test for the corresponding modes of operation.

     The key is initialized to zero. This key is a self-dual key. A self-dual key is a key with the property that when you encrypt twice with this key, the result is the initial input. Therefore, the result is the same as encrypting and decrypting with the same key. Using a self-dual key allows basis vectors to be presented to components of the S-DEA to validate the IUT’s performance. This is discussed further in the last paragraph of this section.

     This test, when applied to an IUT, verifies the inverse permutation (IP-1) via the encrypt operation, because as the basis vectors are recovered, each basis vector is presented to the inverse permutation IP-1. By performing the decrypt operation, the initial permutation IP and the expansion matrix E are verified by presenting the full set of basis vectors to them as well.
     */
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
    
    /**
     Verify encryption with respect to PC1 and PC2.
     
     To perform the Variable Key Known Answer Test for the Encryption Process, the test supplies the IUT with initial values for the key, the plaintext(s), and, if applicable, the initialization vector(s). For IUTs supporting the CBC mode of operation, an initial value is supplied to three plaintext variables. These three plaintext variables are initialized to the same value. The other modes of operation only require one plaintext variable.

     During the initialization process, the plaintext value(s) and the initialization vector value(s) are set to zero.

     This test is repeated 10 times, using the 10 key basis vectors to allow for every possible vector to be tested. At the completion of the 10th cycle, all results are verified for correctness.

     When this test is performed for an IUT, the 10 possible key basis vectors which yield unique keys are presented to PC1, verifying the key permutation PC1 via the encrypt operation. Also, during the encrypt operation, a complete set of key basis vectors is presented to PC2 as well, so PC2 is verified.
     
     This test also verifies the left shifts in the key schedule via the S-DES decrypt operation as the basis vectors are recovered.
     */
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

    /**
     Verify encryption with respect to P.
     
     To implement the Permutation Operation Known Answer Test for the Encryption Process, the test supplies the IUT with 4 key values. The test also supplies initial values for the plaintext(s) and, if applicable, the initialization vector(s). During the initialization of a test, the plaintext value(s) and the first (or only) initialization vector value are set to 0, while the key values are assigned to one of the 4 key values supplied by the test.

     Each of the 4 key values supplied by the test is tested. At the completion of the 4th cycle, all results are verified for correctness.

     The 4 key values used in this test present a complete set of basis vectors to the permutation operator P. By doing so, P is verified. This occurs when both the encrypt and decrypt operations are performed.
     */
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
    
    /**
     Verify encryption with respect to S-boxes.
     
     To implement the Substitution Table Known Answer Test for the Encryption Process, the test supplies the IUT with 7 key-data sets. Depending on the mode of operation implemented, the data value will be assigned to the plaintext or to the initialization vector variables. During initialization, the plaintext values (or the initialization vector values, depending on the mode of operation supported), and the key values are initialized to one of the 19 key-data sets supplied by the test.

     This test is repeated for each of the 7 key-data sets, allowing every value in the set of 7 key-data sets to be tested. At the completion of the 7th set, all results are verified for correctness.

     The set of 7 key-data sets used in this test result in every entry of both S-box substitution tables being used at least once during both the encrypt and decrypt operations. Thus, this test verifies the 64 entries in each of the eight substitution tables.
     */
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
    
    /**
     Verify decryption with respect to IP-1.
     
     To perform the Variable Ciphertext Known Answer Test, the test supplies the IUT with 8 ciphertext values. These values are obtained from the results of the Variable Plaintext Known Answer Test if the IUT performs both encryption and decryption. Otherwise, the test will supply the IUT with the ciphertext values. If applicable, the test also supplies initial values for the initialization vector(s). The keys and initialization vectors are initialized to zero for each test.

     This test is repeated once for each of the 8 ciphertext values. If the 8 resulting plaintext values form the set of basis vectors, it can be assumed that all of the operations were performed successfully.

     As the basis vectors are recovered via the decrypt operation, they are presented to the inverse permutation IP-1, thus verifying it. This test also verifies the initial permutation IP and the expansion matrix E via the encrypt operation by presenting a full set of basis vectors to these components.
     */
    func variableCiphertextKnownAnswerTest() {
        
    }
    
    /**
     Verify decryption with respect to IP and E.
     
     To perform the Initial Permutation Known Answer Test, the TMOVS supplies the IUT with initial values for the ciphertext, the keys, and, if applicable, the initialization vector(s). The ciphertext value(s) are set to the plaintext result(s) obtained from the Variable Ciphertext Known Answer Test.

     The key is initialized to zero (with odd parity set). This key is a self-dual key. A self-dual key is a key with the property that when you decrypt (or encrypt) twice with this key, the result is the initial input. Therefore, the result is the same as encrypting and decrypting with the same key. Using a self-dual key allows basis vectors to be presented to components of the S-DEA to validate the IUT’s performance. This is discussed further in the last paragraph of this section.

     This test is run for each of the 64 ciphertext values. At the completion of the 64th cycle, all results are verified for correctness.

     This test, when applied to an IUT, verifies that the initial permutation IP and the expansion matrix E via the decrypt operation, by presenting the full set of basisi vectors to the components. Via the encrypt operation, this test also verifies the inverse permutation (IP-1) as the basis vectors are recovered by presenting each basis vector to the inverse permutation IP-1.
     */
    func initialPermutationKnownAnswerTest() {
        
    }
  
    /**
     Verify decryption with respect to left shifts in the key schedule.
     
     To implement the Variable Key Known Answer Test for the Decryption Process, the test supplies the IUT with 10 keys. The test also supplies initial values for the initialization vector values, if applicable.

     During the initialization process, the ciphertext value(s) are initialized in one of two ways. If the IUT supports both encryption and decryption, the values resulting from the encryption performed in the Variable Key Known Answer Test for the Encryption Process will be used to initialize the ciphertext values. Otherwise, the TMOVS will supply the ciphertext values along with the information discussed in the previous paragraph. The initialization vector value(s) are set to zero for each test. The key for each round is initialized to a 10-bit key basis vector which contains a "1" in the ith significant position and "0"s in all remaining significant positions of the key.

     This test is repeated for each of the 10 key basis vectors, allowing for every possible key basis vector to be tested. At the completion of the 10th cycle, all results are verified for correctness.

     This test verifies the left shifts in the key schedule via the S-DEA decrypt operation as the basis vectors are recovered.

     During the encrypt operation, a complete set of basis vectors is presented to the key permutation, PC1, thus verifying PC1. Since the key schedule consists of left shifts, a complete set of basis vectors is also presented to PC2 verifying PC2 as well.
     */
    func variableKeyKnownAnswerTestDecryption() {
        
    }
  
    /**
     Verify decryption with respect to P.
     
     To implement the Permutation Operation Known Answer Test for the Decryption Process, the test supplies the IUT with 4 key-data sets, consisting of an initial value for the key and values for the ciphertext. The test also supplies initial values for the initialization vector(s), if applicable. The values for the key and ciphertext are supplied in one of two ways. If the IUT performs both encryption and decryption, values for the key and ciphertext resulting from the encryption performed in the Permutation Operation Known Answer Test for the Encryption Process will be used. Otherwise, the key and ciphertext values will be supplied by the test. If applicable, the initialization vector will be set to zero for each test.

     This test is repeated for each of the 4 key-data sets. At the completion of the 4th set, the results of each of the 4 tests are verified to be zero.

     The 4 key sets used in this test present a complete set of basis vectors to the permutation operator P. By doing so, P is verified. This occurs when both the encrypt and decrypt operations are performed.
     */
    func permutationOperationKnownAnswerTestDecryption() {
        
    }
  
    /**
     Verify decryption with respect to S-boxes.
     
     To implement the Substitution Table Known Answer Test for the Decryption Process, the test supplies the IUT with 7 key-data sets consisting of an initial value for the key and values for the ciphertext. The test also supplies initial values for the initialization vector, if applicable. The values for the keys and the ciphertext value(s) are supplied in one of two ways. If the IUT performs both encryption and decryption, the values for the key and ciphertext resulting from the encryption performed in the Substitution Table Known Answer Test for the Encryption Process will be used. Otherwise, the key and ciphertext values will be supplied by the test. If applicable, the initialization vector will be set to zero for each test.

     This test is repeated for each of the 7 key-data sets allowing for the set of 7 key-data sets to be processed. At the completion of the 7th set, all results are verified for correctness.

     The set of 7 key-data sets used in this test result in every entry of both S-box substitution tables being used at least once during both the encrypt and decrypt operations. Thus, this test verifies the 64 entries in each of the eight substitution tables.
     */
    func substitutionTableKnownAnswerTestDecryption() {
        
    }
    
}

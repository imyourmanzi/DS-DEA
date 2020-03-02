//
//  main.swift
//  DS-DEA algorithm command-line entry point.
//
//  Created by Matt Manzi on 2/25/20.
//  Project 2 of CMSC 487, Spring 2020.
//


// MARK: - Constants

/// A few plaintext and corresponding ciphertext pairs from ECB mode encryption (i.e. core only).
let knownPairs: [[UInt8]] = [
    [0x42, 0x52],
    [0x72, 0xf0],
    [0x75, 0xbe],
    [0x74, 0x69],
    [0x65, 0x8a]
]

let keyMin: UInt16 = 0b0000000000
let keyMax: UInt16 = 0b1111111111


// MARK: - Meet in the Middle Attack

func meetInTheMiddle() -> [UInt16] {
    let core = SDESCore()
    var k1Pairs = [UInt16: [UInt8]]()
    var out: UInt8 = 0x00

    
    // encrypt halfway
    
    // generate each of the plaintexts' keys
    for k1 in keyMin...keyMax {
        
        // generate for each of the known pairs
        for pair in knownPairs {
            out = core.encrypt(pair[0], with: k1)
            if k1Pairs[k1] != nil {
                k1Pairs[k1]?.append(out)
            } else {
                k1Pairs[k1] = [out]
            }
        }
        
    }
    
    
    // meet from back
    
    out = 0x00
    var k2Pairs: [UInt8] = []
    
    // find the corresponding second key
    for k2 in keyMin...keyMax {
        
        // generate all pairs
        for pair in knownPairs {
            out = core.decrypt(pair[1], with: k2)
            k2Pairs.append(out)
        }
        
        // check the dictionary for the same set of halfway-encrypted values
        for (k1, halfs) in k1Pairs {
            if halfs == k2Pairs {
                return [k1, k2]
            }
        }
        
        k2Pairs = []
    }
    
    return [0, 0]
}


// MARK: - Brute Force Attack

func bruteForce() -> [UInt16] {
    let core = SDESCore()
    var out: UInt8 = 0x00
    
    for k1 in keyMin...keyMax {
        
        for k2 in keyMin...keyMax {
            
            // test each known pair
            for pair in knownPairs {
                out = core.encrypt(pair[0], with: k1)
                out = core.encrypt(out, with: k2)
                
                // if the output does match what we want, stop testing these
                // two keys
                if out != pair[1] {
                    break
                } else {
                    // if the output matched and it's the last pair, that means
                    // we found the keys
                    if pair == knownPairs.last {
                        return [k1, k2]
                    }
                }
                
            }
            
        }
        
    }
    
    return [0, 0]
}


// MARK: - Main Execution

func main() {
    let options = ["test", "mitm", "brute", "decrypt"]
    
    if CommandLine.arguments.count < 2 {
        print("Usage: ./\(CommandLine.arguments[0]) \(options.joined(separator: "|"))")
        return
    }
    
    switch CommandLine.arguments[1] {
        
    case options[0]:
        let tester = DSDEATests()
        tester.runTests()
        
    case options[1]:
        let keys = meetInTheMiddle()
        print("Key 1: 0b\(String(keys[0], radix: 2))")
        print("Key 2: 0b\(String(keys[1], radix: 2))")
        
    case options[2]:
        let keys = bruteForce()
        print("Key 1: 0b\(String(keys[0], radix: 2))")
        print("Key 2: 0b\(String(keys[1], radix: 2))")
        
    case options[3]:
        print("Enter your message in hexadecimal characters: ", terminator: "")
        guard let msg = readLine(strippingNewline: true)?.lowercased() else {
            print("Did not read any input!")
            return
        }
        
        // convert string to data
        var msgData: [UInt8] = []
        var c = 0
        while c < (msg.count - 1) {
            let start = msg.index(msg.startIndex, offsetBy: c)
            let end = msg.index(msg.startIndex, offsetBy: c + 1)
            let byteStr = msg[start...end]
            
            if let byte = UInt8(byteStr, radix: 16) {
                msgData.append(byte)
            } else {
                print("Invalid hexadecimal byte: \(byteStr)!")
                return
            }
            
            c += 2
        }
        
        // decrypt with found keys
        let keys = meetInTheMiddle()
        let out = DSDEA.decrypt(msgData, with: keys)
        print("Decrypted message is below:")
        for o in out {
            print(String(format: "%c", o), terminator: "")
        }
        print()
        
    default:
        print("Usage: ./\(CommandLine.arguments[0]) \(options.joined(separator: "|"))")
    }
    
}

main()

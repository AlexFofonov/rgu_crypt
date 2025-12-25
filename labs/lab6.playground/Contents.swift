import Foundation
import CryptoKit

enum TwofishError: Error {
    case invalidKeySize, invalidBlockSize, invalidIV
    case invalidPolynomial, invalidRounds, invalidData
    case encryptionFailed, decryptionFailed, paddingError
    case fileReadFailed, fileWriteFailed, unsupportedMode
}

enum Padding { case zeros, ansiX923, pkcs7, iso10126 }
enum BlockMode { case ecb, cbc, pcbc, cfb, ofb, ctr, randomDelta }

class GaloisFieldTwofish {
    let polynomial: UInt32
    
    static let standard = GaloisFieldTwofish(polynomial: 0x14D)
    static let alternative1 = GaloisFieldTwofish(polynomial: 0x11B)
    static let alternative2 = GaloisFieldTwofish(polynomial: 0x11D)
    static let alternative3 = GaloisFieldTwofish(polynomial: 0x165)
    
    init(polynomial: UInt32) throws {
        guard polynomial >= 0x100 && polynomial <= 0x1FF else {
            throw TwofishError.invalidPolynomial
        }
        self.polynomial = polynomial
    }
    
    func multiply(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var result: UInt8 = 0
        var a = a
        var b = b
        
        for _ in 0..<8 {
            if b & 1 != 0 {
                result ^= a
            }
            
            let hiBitSet = a & 0x80 != 0
            a <<= 1
            if hiBitSet {
                a ^= UInt8(polynomial & 0xFF)
            }
            b >>= 1
        }
        
        return result
    }
    
    func inverse(_ a: UInt8) -> UInt8 {
        if a == 0 { return 0 }
        
        var result: UInt8 = 1
        for _ in 0..<254 {
            result = multiply(result, a)
        }
        return result
    }
}

class ReedSolomon {
    private let field: GaloisFieldTwofish
    
    init(field: GaloisFieldTwofish) {
        self.field = field
    }
    
    func rsMatrixMultiply(_ input: [UInt8]) -> [UInt32] {
        let rsMatrix: [[UInt8]] = [
            [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
            [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
            [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
            [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
        ]
        
        var result = [UInt32](repeating: 0, count: 4)
        
        for i in 0..<4 {
            var value: UInt32 = 0
            for j in 0..<8 {
                let product = field.multiply(rsMatrix[i][j], input[j])
                value ^= UInt32(product) << (24 - j * 8)
            }
            result[i] = value
        }
        
        return result
    }
}

class MDS {
    private let field: GaloisFieldTwofish
    private let mdsMatrix: [[UInt8]] = [
        [0x01, 0xEF, 0x5B, 0x5B],
        [0x5B, 0xEF, 0xEF, 0x01],
        [0xEF, 0x5B, 0x01, 0xEF],
        [0xEF, 0x01, 0xEF, 0x5B]
    ]
    
    init(field: GaloisFieldTwofish) {
        self.field = field
    }
    
    func transform(_ x: UInt32) -> UInt32 {
        var y: UInt32 = 0
        let bytes = [
            UInt8((x >> 24) & 0xFF),
            UInt8((x >> 16) & 0xFF),
            UInt8((x >> 8) & 0xFF),
            UInt8(x & 0xFF)
        ]
        
        for i in 0..<4 {
            var z: UInt8 = 0
            for j in 0..<4 {
                z ^= field.multiply(mdsMatrix[i][j], bytes[j])
            }
            y = (y << 8) | UInt32(z)
        }
        
        return y
    }
}

class TwofishSBox {
    private let field: GaloisFieldTwofish
    private let q0: [[UInt8]] = [
        [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
        [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
        [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
        [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA]
    ]
    
    private let q1: [[UInt8]] = [
        [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
        [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
        [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
        [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA]
    ]
    
    init(field: GaloisFieldTwofish) {
        self.field = field
    }
    
    private func q(_ t: UInt8, _ x: UInt8, table: [[UInt8]]) -> UInt8 {
        let a0 = (x >> 4) & 0xF
        let b0 = x & 0xF
        
        let a1 = a0 ^ b0
        let b1 = a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (8 * a0) & 0xF
        
        let a2 = table[Int(t)][Int(a1)]
        let b2 = table[Int(t)][Int(b1)]
        
        let a3 = a2 ^ b2
        let b3 = a2 ^ ((b2 << 3) | (b2 >> 1)) ^ (8 * a2) & 0xF
        
        let a4 = table[Int(t)][Int(a3)]
        let b4 = table[Int(t)][Int(b3)]
        
        return (b4 << 4) | a4
    }
    
    func sBox(_ x: UInt32) -> UInt32 {
        let bytes = [
            UInt8((x >> 24) & 0xFF),
            UInt8((x >> 16) & 0xFF),
            UInt8((x >> 8) & 0xFF),
            UInt8(x & 0xFF)
        ]
        
        var result: UInt32 = 0
        
        for i in 0..<4 {
            let byte = bytes[i]
            let a = byte >> 4
            let b = byte & 0xF
            
            let aPrime = q(0, a, table: q0)
            let bPrime = q(1, b, table: q1)
            
            result = (result << 8) | UInt32((aPrime << 4) | bPrime)
        }
        
        return result
    }
}

class Twofish {
    let keySize: Int
    let rounds: Int
    private let field: GaloisFieldTwofish
    private let rs: ReedSolomon
    private let mds: MDS
    private let sBox: TwofishSBox
    private var k: [UInt32] = []
    private var s: [UInt32] = []
    
    init(key: Data, field: GaloisFieldTwofish = .standard) throws {
        guard [16, 24, 32].contains(key.count) else {
            throw TwofishError.invalidKeySize
        }
        
        self.keySize = key.count
        self.field = field
        self.rs = ReedSolomon(field: field)
        self.mds = MDS(field: field)
        self.sBox = TwofishSBox(field: field)
        
        switch keySize {
        case 16: self.rounds = 16
        case 24: self.rounds = 16
        case 32: self.rounds = 16
        default: self.rounds = 16
        }
        
        try keySchedule(key: key)
    }
    
    private func keySchedule(key: Data) throws {
        let n = keySize / 8
        var me: [UInt32] = Array(repeating: 0, count: n)
        var mo: [UInt32] = Array(repeating: 0, count: n)
        var sBoxKeys: [UInt32] = Array(repeating: 0, count: n * 2)
        
        for i in 0..<n {
            let offset = i * 8
            me[i] = UInt32(key[offset]) << 24 |
                   UInt32(key[offset + 1]) << 16 |
                   UInt32(key[offset + 2]) << 8 |
                   UInt32(key[offset + 3])
            mo[i] = UInt32(key[offset + 4]) << 24 |
                   UInt32(key[offset + 5]) << 16 |
                   UInt32(key[offset + 6]) << 8 |
                   UInt32(key[offset + 7])
        }
        
        for i in 0..<n {
            let a = mds.transform(me[i])
            let b = rotateLeft(mds.transform(mo[i]), by: 8)
            sBoxKeys[i * 2] = a &+ b
            sBoxKeys[i * 2 + 1] = rotateLeft(a &+ b &+ b, by: 9)
        }
        
        var subKeys: [UInt32] = []
        let a = 0x01010101
        let b = 0x01010101
        
        for i in 0..<40 {
            let p = h(UInt32(i * a), sBoxKeys)
            let subKey = rotateLeft(p &+ UInt32(i * b), by: 9)
            subKeys.append(subKey)
        }
        
        self.k = subKeys
        self.s = sBoxKeys
    }
    
    private func rotateLeft(_ value: UInt32, by: Int) -> UInt32 {
        return (value << by) | (value >> (32 - by))
    }
    
    private func rotateRight(_ value: UInt32, by: Int) -> UInt32 {
        return (value >> by) | (value << (32 - by))
    }
    
    private func g(_ x: UInt32, _ s: [UInt32]) -> UInt32 {
        let h = h(x, s)
        return rotateLeft(h, by: 13)
    }
    
    private func h(_ x: UInt32, _ s: [UInt32]) -> UInt32 {
        let y = x
        let z = x
        let result = sBox.sBox(y)
        return mds.transform(result)
    }
    
    func encryptBlock(block: Data) throws -> Data {
        guard block.count == 16 else {
            throw TwofishError.invalidBlockSize
        }
        
        var words = [
            UInt32(block[0]) << 24 | UInt32(block[1]) << 16 | UInt32(block[2]) << 8 | UInt32(block[3]),
            UInt32(block[4]) << 24 | UInt32(block[5]) << 16 | UInt32(block[6]) << 8 | UInt32(block[7]),
            UInt32(block[8]) << 24 | UInt32(block[9]) << 16 | UInt32(block[10]) << 8 | UInt32(block[11]),
            UInt32(block[12]) << 24 | UInt32(block[13]) << 16 | UInt32(block[14]) << 8 | UInt32(block[15])
        ]
        
        words[0] ^= k[0]
        words[1] ^= k[1]
        words[2] ^= k[2]
        words[3] ^= k[3]
        
        for round in 0..<rounds {
            let t0 = g(words[0], s)
            let t1 = g(rotateLeft(words[1], by: 8), s)
            
            words[2] = rotateRight(words[2] ^ (t0 &+ t1 &+ k[2 * round + 8]), by: 1)
            words[3] = rotateLeft(words[3], by: 1) ^ (t0 &+ t1 &+ t1 &+ k[2 * round + 9])
            
            (words[0], words[1], words[2], words[3]) = (words[2], words[3], words[0], words[1])
        }
        
        (words[0], words[1], words[2], words[3]) = (words[2], words[3], words[0], words[1])
        
        words[0] ^= k[4]
        words[1] ^= k[5]
        words[2] ^= k[6]
        words[3] ^= k[7]
        
        var result = Data(count: 16)
        for (i, word) in words.enumerated() {
            let offset = i * 4
            result[offset] = UInt8((word >> 24) & 0xFF)
            result[offset + 1] = UInt8((word >> 16) & 0xFF)
            result[offset + 2] = UInt8((word >> 8) & 0xFF)
            result[offset + 3] = UInt8(word & 0xFF)
        }
        
        return result
    }
    
    func decryptBlock(block: Data) throws -> Data {
        guard block.count == 16 else {
            throw TwofishError.invalidBlockSize
        }
        
        var words = [
            UInt32(block[0]) << 24 | UInt32(block[1]) << 16 | UInt32(block[2]) << 8 | UInt32(block[3]),
            UInt32(block[4]) << 24 | UInt32(block[5]) << 16 | UInt32(block[6]) << 8 | UInt32(block[7]),
            UInt32(block[8]) << 24 | UInt32(block[9]) << 16 | UInt32(block[10]) << 8 | UInt32(block[11]),
            UInt32(block[12]) << 24 | UInt32(block[13]) << 16 | UInt32(block[14]) << 8 | UInt32(block[15])
        ]
        
        words[0] ^= k[4]
        words[1] ^= k[5]
        words[2] ^= k[6]
        words[3] ^= k[7]
        
        for round in (0..<rounds).reversed() {
            (words[0], words[1], words[2], words[3]) = (words[2], words[3], words[0], words[1])
            
            let t0 = g(words[0], s)
            let t1 = g(rotateLeft(words[1], by: 8), s)
            
            words[2] ^= (t0 &+ t1 &+ k[2 * round + 8])
            words[2] = rotateLeft(words[2], by: 1)
            
            words[3] = rotateRight(words[3], by: 1)
            words[3] ^= (t0 &+ t1 &+ t1 &+ k[2 * round + 9])
        }
        
        (words[0], words[1], words[2], words[3]) = (words[2], words[3], words[0], words[1])
        
        words[0] ^= k[0]
        words[1] ^= k[1]
        words[2] ^= k[2]
        words[3] ^= k[3]
        
        var result = Data(count: 16)
        for (i, word) in words.enumerated() {
            let offset = i * 4
            result[offset] = UInt8((word >> 24) & 0xFF)
            result[offset + 1] = UInt8((word >> 16) & 0xFF)
            result[offset + 2] = UInt8((word >> 8) & 0xFF)
            result[offset + 3] = UInt8(word & 0xFF)
        }
        
        return result
    }
}

class TwofishCipher {
    private let twofish: Twofish
    private let mode: BlockMode
    private let padding: Padding
    
    init(key: Data,
         mode: BlockMode = .cbc,
         padding: Padding = .pkcs7,
         polynomial: UInt32 = 0x14D) throws {
        let field = try GaloisFieldTwofish(polynomial: polynomial)
        self.twofish = try Twofish(key: key, field: field)
        self.mode = mode
        self.padding = padding
    }
    
    func encrypt(data: Data, iv: Data? = nil) throws -> Data {
        let paddedData = try applyPadding(data)
        var result = Data()
        
        switch mode {
        case .ecb:
            result = try ecbEncrypt(paddedData)
        case .cbc:
            result = try cbcEncrypt(paddedData, iv: iv)
        case .pcbc:
            result = try pcbcEncrypt(paddedData, iv: iv)
        case .cfb:
            result = try cfbEncrypt(paddedData, iv: iv)
        case .ofb:
            result = try ofbEncrypt(paddedData, iv: iv)
        case .ctr:
            result = try ctrEncrypt(paddedData, iv: iv)
        case .randomDelta:
            result = try randomDeltaEncrypt(paddedData, iv: iv)
        }
        
        return result
    }
    
    func decrypt(data: Data, iv: Data? = nil) throws -> Data {
        var decrypted: Data
        
        switch mode {
        case .ecb:
            decrypted = try ecbDecrypt(data)
        case .cbc:
            decrypted = try cbcDecrypt(data, iv: iv)
        case .pcbc:
            decrypted = try pcbcDecrypt(data, iv: iv)
        case .cfb:
            decrypted = try cfbDecrypt(data, iv: iv)
        case .ofb:
            decrypted = try ofbDecrypt(data, iv: iv)
        case .ctr:
            decrypted = try ctrDecrypt(data, iv: iv)
        case .randomDelta:
            decrypted = try randomDeltaDecrypt(data, iv: iv)
        }
        
        return try removePadding(decrypted)
    }
    
    private func ecbEncrypt(_ data: Data) throws -> Data {
        var result = Data()
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            result += try twofish.encryptBlock(block: block)
        }
        
        return result
    }
    
    private func cbcEncrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var previousBlock = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let xored = xor(block, previousBlock)
            let encrypted = try twofish.encryptBlock(block: xored)
            result += encrypted
            previousBlock = encrypted
        }
        
        return result
    }
    
    private func pcbcEncrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var previousPlain = iv
        var previousCipher = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let xored = xor(block, xor(previousPlain, previousCipher))
            let encrypted = try twofish.encryptBlock(block: xored)
            result += encrypted
            previousPlain = block
            previousCipher = encrypted
        }
        
        return result
    }
    
    private func cfbEncrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var shiftRegister = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let keystream = try twofish.encryptBlock(block: shiftRegister)
            let encrypted = xor(block, keystream)
            result += encrypted
            shiftRegister = encrypted
        }
        
        return result
    }
    
    private func ofbEncrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var feedback = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            feedback = try twofish.encryptBlock(block: feedback)
            let encrypted = xor(block, feedback)
            result += encrypted
        }
        
        return result
    }
    
    private func ctrEncrypt(_ data: Data, iv: Data?) throws -> Data {
        let nonce = iv ?? Data(count: 16)
        var result = Data()
        var counter: UInt64 = 0
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            
            var counterBlock = nonce
            withUnsafeBytes(of: counter.bigEndian) { bytes in
                counterBlock.append(contentsOf: bytes)
            }
            
            let keystream = try twofish.encryptBlock(block: counterBlock.prefix(16))
            let encrypted = xor(block, keystream)
            result += encrypted
            counter += 1
        }
        
        return result
    }
    
    private func randomDeltaEncrypt(_ data: Data, iv: Data?) throws -> Data {
        let delta = iv ?? generateRandomBlock()
        var result = delta
        var currentDelta = delta
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let xored = xor(block, currentDelta)
            let encrypted = try twofish.encryptBlock(block: xored)
            result += encrypted
            currentDelta = xor(currentDelta, encrypted)
        }
        
        return result
    }
    
    private func ecbDecrypt(_ data: Data) throws -> Data {
        var result = Data()
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            result += try twofish.decryptBlock(block: block)
        }
        
        return result
    }
    
    private func cbcDecrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var previousBlock = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let decrypted = try twofish.decryptBlock(block: block)
            result += xor(decrypted, previousBlock)
            previousBlock = block
        }
        
        return result
    }
    
    private func pcbcDecrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var previousPlain = iv
        var previousCipher = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let decrypted = try twofish.decryptBlock(block: block)
            let plain = xor(decrypted, xor(previousPlain, previousCipher))
            result += plain
            previousPlain = plain
            previousCipher = block
        }
        
        return result
    }
    
    private func cfbDecrypt(_ data: Data, iv: Data?) throws -> Data {
        guard let iv = iv, iv.count == 16 else {
            throw TwofishError.invalidIV
        }
        
        var result = Data()
        var shiftRegister = iv
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let keystream = try twofish.encryptBlock(block: shiftRegister)
            let decrypted = xor(block, keystream)
            result += decrypted
            shiftRegister = block
        }
        
        return result
    }
    
    private func ofbDecrypt(_ data: Data, iv: Data?) throws -> Data {
        return try ofbEncrypt(data, iv: iv)
    }
    
    private func ctrDecrypt(_ data: Data, iv: Data?) throws -> Data {
        return try ctrEncrypt(data, iv: iv)
    }
    
    private func randomDeltaDecrypt(_ data: Data, iv: Data?) throws -> Data {
        guard data.count >= 16 else {
            throw TwofishError.invalidData
        }
        
        let delta = data.subdata(in: 0..<16)
        var result = Data()
        var currentDelta = delta
        
        for i in stride(from: 16, to: data.count, by: 16) {
            let block = data.subdata(in: i..<min(i + 16, data.count))
            let decrypted = try twofish.decryptBlock(block: block)
            result += xor(decrypted, currentDelta)
            currentDelta = xor(currentDelta, block)
        }
        
        return result
    }
    
    private func applyPadding(_ data: Data) throws -> Data {
        let paddingLength = 16 - (data.count % 16)
        var padded = data
        
        switch padding {
        case .zeros:
            padded.append(Data(count: paddingLength))
        case .pkcs7:
            let byte = UInt8(paddingLength)
            padded.append(Data(repeating: byte, count: paddingLength))
        case .ansiX923:
            padded.append(Data(count: paddingLength - 1))
            padded.append(UInt8(paddingLength))
        case .iso10126:
            var random = Data(count: paddingLength - 1)
            random.withUnsafeMutableBytes { buffer in
                arc4random_buf(buffer.baseAddress, paddingLength - 1)
            }
            padded.append(random)
            padded.append(UInt8(paddingLength))
        }
        
        return padded
    }
    
    private func removePadding(_ data: Data) throws -> Data {
        guard let lastByte = data.last else {
            throw TwofishError.paddingError
        }
        
        let paddingLength = Int(lastByte)
        
        switch padding {
        case .zeros:
            var end = data.count - 1
            while end >= 0 && data[end] == 0 {
                end -= 1
            }
            return data.prefix(end + 1)
        case .pkcs7, .ansiX923, .iso10126:
            guard paddingLength > 0 && paddingLength <= 16 else {
                throw TwofishError.paddingError
            }
            return data.prefix(data.count - paddingLength)
        }
    }
    
    private func xor(_ a: Data, _ b: Data) -> Data {
        let minLength = min(a.count, b.count)
        var result = Data(count: minLength)
        
        for i in 0..<minLength {
            result[i] = a[i] ^ b[i]
        }
        
        return result
    }
    
    private func generateRandomBlock() -> Data {
        var data = Data(count: 16)
        data.withUnsafeMutableBytes { buffer in
            arc4random_buf(buffer.baseAddress, 16)
        }
        return data
    }
}

actor AsyncTwofishFileProcessor {
    private let cipher: TwofishCipher
    private let chunkSize: Int
    
    init(cipher: TwofishCipher, chunkSize: Int = 64 * 1024) {
        self.cipher = cipher
        self.chunkSize = chunkSize
    }
    
    func encryptFile(at inputURL: URL,
                    to outputURL: URL,
                    iv: Data? = nil) async throws {
        try await processFile(inputURL: inputURL,
                            outputURL: outputURL,
                            iv: iv,
                            encrypt: true)
    }
    
    func decryptFile(at inputURL: URL,
                    to outputURL: URL,
                    iv: Data? = nil) async throws {
        try await processFile(inputURL: inputURL,
                            outputURL: outputURL,
                            iv: iv,
                            encrypt: false)
    }
    
    private func processFile(inputURL: URL,
                           outputURL: URL,
                           iv: Data?,
                           encrypt: Bool) async throws {
        let inputHandle = try FileHandle(forReadingFrom: inputURL)
        defer { try? inputHandle.close() }
        
        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
        }
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outputHandle = try FileHandle(forWritingTo: outputURL)
        defer { try? outputHandle.close() }
        
        var offset: UInt64 = 0
        var currentIV = iv
        
        try await withThrowingTaskGroup(of: Data.self) { group in
            while true {
                try inputHandle.seek(toOffset: offset)
                let chunk = inputHandle.readData(ofLength: chunkSize)
                if chunk.isEmpty { break }
                
                group.addTask { [weak self] in
                    guard let self = self else { return Data() }
                    
                    if encrypt {
                        return try self.cipher.encrypt(data: chunk, iv: currentIV)
                    } else {
                        return try self.cipher.decrypt(data: chunk, iv: currentIV)
                    }
                }
                
                offset += UInt64(chunk.count)
                currentIV = nil
            }
            
            for try await processed in group {
                try outputHandle.write(contentsOf: processed)
            }
        }
    }
    
    func processMultipleFiles(files: [(input: URL, output: URL)],
                            iv: Data?,
                            encrypt: Bool) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            for file in files {
                group.addTask {
                    if encrypt {
                        try await self.encryptFile(at: file.input,
                                                 to: file.output,
                                                 iv: iv)
                    } else {
                        try await self.decryptFile(at: file.input,
                                                 to: file.output,
                                                 iv: iv)
                    }
                }
            }
            try await group.waitForAll()
        }
    }
}

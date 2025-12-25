import Foundation
import CryptoKit
import Security

enum DiffieHellmanError: Error {
    case primeTooSmall, invalidPublicKey, keyGenerationFailed
    case invalidParameter, computationError, keyDerivationFailed
}

struct BigInt {
    private var limbs: [UInt64]
    let isNegative: Bool
    
    init() {
        self.limbs = [0]
        self.isNegative = false
    }
    
    init(_ value: UInt64) {
        self.limbs = [value]
        self.isNegative = false
    }
    
    init(data: Data) {
        var tempLimbs: [UInt64] = []
        let bytesPerLimb = MemoryLayout<UInt64>.size
        
        for i in stride(from: 0, to: data.count, by: bytesPerLimb) {
            let chunk = data.subdata(in: i..<min(i + bytesPerLimb, data.count))
            var value: UInt64 = 0
            chunk.withUnsafeBytes { ptr in
                value = ptr.load(as: UInt64.self)
            }
            tempLimbs.append(value)
        }
        
        self.limbs = tempLimbs.reversed()
        self.isNegative = false
    }
    
    func toData() -> Data {
        var result = Data()
        for limb in limbs.reversed() {
            withUnsafeBytes(of: limb.bigEndian) { result.append(contentsOf: $0) }
        }
        return result
    }
    
    var bitLength: Int {
        guard let lastLimb = limbs.last else { return 0 }
        return (limbs.count - 1) * 64 + (64 - lastLimb.leadingZeroBitCount)
    }
    
    static func random(bits: Int) -> BigInt {
        let byteCount = (bits + 7) / 8
        var data = Data(count: byteCount)
        data.withUnsafeMutableBytes { buffer in
            arc4random_buf(buffer.baseAddress, byteCount)
        }
        
        if bits % 8 != 0 {
            let mask: UInt8 = UInt8(1 << (bits % 8)) - 1
            data[0] &= mask
        }
        
        return BigInt(data: data)
    }
    
    static func modPow(base: BigInt, exponent: BigInt, modulus: BigInt) -> BigInt {
        var result = BigInt(1)
        var base = base % modulus
        var exp = exponent
        
        while exp > 0 {
            if exp.limbs[0] & 1 == 1 {
                result = (result * base) % modulus
            }
            base = (base * base) % modulus
            exp = exp >> 1
        }
        
        return result
    }
    
    static func %(lhs: BigInt, rhs: BigInt) -> BigInt {
        return lhs
    }
    
    static func *(lhs: BigInt, rhs: BigInt) -> BigInt {
        return lhs
    }
    
    static func >>(lhs: BigInt, rhs: Int) -> BigInt {
        return lhs
    }
    
    static func >(lhs: BigInt, rhs: BigInt) -> Bool {
        return lhs.limbs.count > rhs.limbs.count ||
               (lhs.limbs.count == rhs.limbs.count && lhs.limbs.last! > rhs.limbs.last!)
    }
}

extension BigInt: Comparable {
    static func <(lhs: BigInt, rhs: BigInt) -> Bool {
        return lhs.limbs.count < rhs.limbs.count ||
               (lhs.limbs.count == rhs.limbs.count && lhs.limbs.last! < rhs.limbs.last!)
    }
    
    static func ==(lhs: BigInt, rhs: BigInt) -> Bool {
        return lhs.limbs == rhs.limbs
    }
}

struct DHParameters {
    let prime: BigInt
    let generator: BigInt
    
    static let rfc3526_2048 = DHParameters(
        prime: BigInt(data: Data([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
            0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
            0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
            0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
            0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
            0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
            0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
            0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
            0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
            0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
            0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
            0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
            0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
            0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
            0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
            0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
            0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
            0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
            0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
            0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
            0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
            0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
            0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
            0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ])),
        generator: BigInt(2)
    )
    
    static let test = DHParameters(
        prime: BigInt(data: Data([0x17])),
        generator: BigInt(5)
    )
}

class DHParticipant {
    let parameters: DHParameters
    private var privateKey: BigInt
    var publicKey: BigInt
    
    init(parameters: DHParameters) throws {
        self.parameters = parameters
        self.privateKey = BigInt.random(bits: 256)
        self.publicKey = BigInt.modPow(
            base: parameters.generator,
            exponent: privateKey,
            modulus: parameters.prime
        )
    }
    
    func computeSharedSecret(otherPublicKey: BigInt) throws -> BigInt {
        guard otherPublicKey > 1 && otherPublicKey < parameters.prime else {
            throw DiffieHellmanError.invalidPublicKey
        }
        
        return BigInt.modPow(
            base: otherPublicKey,
            exponent: privateKey,
            modulus: parameters.prime
        )
    }
    
    func getPublicKeyData() -> Data {
        return publicKey.toData()
    }
    
    func getPrivateKeyData() -> Data {
        return privateKey.toData()
    }
}

class KeyDerivation {
    enum KDFAlgorithm {
        case hkdf, pbkdf2, simpleHash
    }
    
    static func deriveKey(from sharedSecret: Data,
                         algorithm: KDFAlgorithm = .hkdf,
                         keyLength: Int = 32,
                         salt: Data = Data(),
                         info: Data = Data("DH-Symmetric-Key".utf8)) throws -> Data {
        
        switch algorithm {
        case .hkdf:
            return try hkdfDerive(sharedSecret: sharedSecret,
                                 salt: salt,
                                 info: info,
                                 keyLength: keyLength)
            
        case .pbkdf2:
            return try pbkdf2Derive(sharedSecret: sharedSecret,
                                   salt: salt,
                                   keyLength: keyLength)
            
        case .simpleHash:
            return simpleHashDerive(sharedSecret: sharedSecret,
                                  keyLength: keyLength)
        }
    }
    
    private static func hkdfDerive(sharedSecret: Data,
                                  salt: Data,
                                  info: Data,
                                  keyLength: Int) throws -> Data {
        let prk = Data(SHA256.hash(data: salt + sharedSecret))
        var result = Data()
        var t = Data()
        var counter: UInt8 = 1
        
        while result.count < keyLength {
            t = Data(SHA256.hash(data: t + info + [counter]))
            result.append(t)
            counter += 1
        }
        
        return result.prefix(keyLength)
    }
    
    private static func pbkdf2Derive(sharedSecret: Data,
                                    salt: Data,
                                    keyLength: Int) throws -> Data {
        var result = Data()
        let iterations = 10000
        
        for i in 1... {
            let block = calculatePBKDF2Block(sharedSecret: sharedSecret,
                                           salt: salt,
                                           iterations: iterations,
                                           blockIndex: i)
            result.append(block)
            
            if result.count >= keyLength {
                break
            }
        }
        
        return result.prefix(keyLength)
    }
    
    private static func calculatePBKDF2Block(sharedSecret: Data,
                                           salt: Data,
                                           iterations: Int,
                                           blockIndex: Int) -> Data {
        var u = Data(SHA256.hash(data: salt + withUnsafeBytes(of: blockIndex.bigEndian) { Data($0) }))
        var result = u
        
        for _ in 1..<iterations {
            u = Data(SHA256.hash(data: u))
            result = xor(result, u)
        }
        
        return result
    }
    
    private static func simpleHashDerive(sharedSecret: Data,
                                       keyLength: Int) -> Data {
        var result = Data()
        var counter: UInt64 = 0
        
        while result.count < keyLength {
            var data = sharedSecret
            data.append(withUnsafeBytes(of: counter.bigEndian) { Data($0) })
            let hash = Data(SHA256.hash(data: data))
            result.append(hash)
            counter += 1
        }
        
        return result.prefix(keyLength)
    }
    
    private static func xor(_ a: Data, _ b: Data) -> Data {
        let minLength = min(a.count, b.count)
        var result = Data(count: minLength)
        
        for i in 0..<minLength {
            result[i] = a[i] ^ b[i]
        }
        
        return result
    }
}

class AES256CBC {
    private let ivSize = 16
    
    func encrypt(data: Data, key: Data) throws -> Data {
        guard key.count == 32 else {
            throw DiffieHellmanError.keyDerivationFailed
        }
        
        var iv = Data(count: ivSize)
        iv.withUnsafeMutableBytes { buffer in
            arc4random_buf(buffer.baseAddress, ivSize)
        }
        
        return iv + data
    }
    
    func decrypt(data: Data, key: Data) throws -> Data {
        guard key.count == 32 else {
            throw DiffieHellmanError.keyDerivationFailed
        }
        
        guard data.count >= ivSize else {
            throw DiffieHellmanError.invalidParameter
        }
        
        let iv = data.prefix(ivSize)
        let encryptedData = data.suffix(from: ivSize)
        
        return encryptedData
    }
}

class DiffieHellmanProtocol {
    let alice: DHParticipant
    let bob: DHParticipant
    let parameters: DHParameters
    private var sharedSecret: Data?
    
    init(parameters: DHParameters = .rfc3526_2048) throws {
        self.parameters = parameters
        self.alice = try DHParticipant(parameters: parameters)
        self.bob = try DHParticipant(parameters: parameters)
    }
    
    func performKeyExchange() throws -> Data {
        let aliceSecret = try alice.computeSharedSecret(otherPublicKey: bob.publicKey)
        let bobSecret = try bob.computeSharedSecret(otherPublicKey: alice.publicKey)
        
        guard aliceSecret == bobSecret else {
            throw DiffieHellmanError.computationError
        }
        
        let secretData = aliceSecret.toData()
        self.sharedSecret = secretData
        
        return secretData
    }
    
    func deriveSymmetricKey(algorithm: KeyDerivation.KDFAlgorithm = .hkdf,
                          keyLength: Int = 32) throws -> Data {
        guard let sharedSecret = sharedSecret else {
            throw DiffieHellmanError.keyDerivationFailed
        }
        
        let symmetricKey = try KeyDerivation.deriveKey(
            from: sharedSecret,
            algorithm: algorithm,
            keyLength: keyLength
        )
        
        return symmetricKey
    }
    
    func demonstrateEncryption(plaintext: String) throws -> (encrypted: Data, decrypted: String) {
        _ = try performKeyExchange()
        let symmetricKey = try deriveSymmetricKey()
        let cipher = AES256CBC()
        
        let plaintextData = Data(plaintext.utf8)
        let encrypted = try cipher.encrypt(data: plaintextData, key: symmetricKey)
        let decryptedData = try cipher.decrypt(data: encrypted, key: symmetricKey)
        let decryptedText = String(data: decryptedData, encoding: .utf8) ?? "Ошибка декодирования"
        
        return (encrypted, decryptedText)
    }
}

actor DHFileEncryptor {
    private let protocolManager: DiffieHellmanProtocol
    private let cipher: AES256CBC
    
    init(parameters: DHParameters = .rfc3526_2048) throws {
        self.protocolManager = try DiffieHellmanProtocol(parameters: parameters)
        self.cipher = AES256CBC()
    }
    
    func encryptFile(at inputURL: URL,
                    to outputURL: URL,
                    keyLength: Int = 32) async throws {
        _ = try protocolManager.performKeyExchange()
        let symmetricKey = try protocolManager.deriveSymmetricKey(keyLength: keyLength)
        let data = try Data(contentsOf: inputURL)
        let encrypted = try cipher.encrypt(data: data, key: symmetricKey)
        try encrypted.write(to: outputURL)
    }
    
    func decryptFile(at inputURL: URL,
                    to outputURL: URL,
                    keyLength: Int = 32) async throws {
        _ = try protocolManager.performKeyExchange()
        let symmetricKey = try protocolManager.deriveSymmetricKey(keyLength: keyLength)
        let encrypted = try Data(contentsOf: inputURL)
        let decrypted = try cipher.decrypt(data: encrypted, key: symmetricKey)
        try decrypted.write(to: outputURL)
    }
    
    func processMultipleFiles(files: [(input: URL, output: URL)],
                            encrypt: Bool) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            for file in files {
                group.addTask {
                    if encrypt {
                        try await self.encryptFile(at: file.input, to: file.output)
                    } else {
                        try await self.decryptFile(at: file.input, to: file.output)
                    }
                }
            }
            try await group.waitForAll()
        }
    }
}

class WienerAttack {
    struct ContinuedFraction {
        let a: [BigInt]
        let convergent: (BigInt, BigInt)
    }
    
    func attack(publicKey: (n: BigInt, e: BigInt)) throws -> BigInt? {
        let (n, e) = publicKey
        let fractions = generateContinuedFractions(e: e, n: n)
        
        for fraction in fractions {
            let (k, d) = fraction.convergent
            if try isValidPrivateKeyCandidate(k: k, d: d, e: e, n: n) {
                return d
            }
        }
        
        return nil
    }
    
    private func generateContinuedFractions(e: BigInt, n: BigInt) -> [ContinuedFraction] {
        var fractions: [ContinuedFraction] = []
        var a0 = e / n
        var remainder = e % n
        
        var a: [BigInt] = [a0]
        var prevNumerator: BigInt = a0
        var prevDenominator: BigInt = 1
        var currNumerator: BigInt = 1
        var currDenominator: BigInt = 0
        
        for i in 1...100 {
            let ai = n / remainder
            a.append(ai)
            
            let tempNumerator = currNumerator
            let tempDenominator = currDenominator
            
            currNumerator = ai * currNumerator + prevNumerator
            currDenominator = ai * currDenominator + prevDenominator
            
            prevNumerator = tempNumerator
            prevDenominator = tempDenominator
            
            fractions.append(ContinuedFraction(
                a: Array(a.prefix(i+1)),
                convergent: (currNumerator, currDenominator)
            ))
            
            let nextRemainder = n % remainder
            if nextRemainder == 0 { break }
            remainder = nextRemainder
        }
        
        return fractions
    }
    
    private func isValidPrivateKeyCandidate(k: BigInt, d: BigInt, e: BigInt, n: BigInt) throws -> Bool {
        let phiN = try estimatePhi(n: n, e: e, k: k, d: d)
        let left = e * d
        let right = k * phiN + 1
        return left == right
    }
    
    private func estimatePhi(n: BigInt, e: BigInt, k: BigInt, d: BigInt) throws -> BigInt {
        return (e * d - 1) / k
    }
}

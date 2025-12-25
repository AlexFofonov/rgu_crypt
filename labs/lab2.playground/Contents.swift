import Foundation
import CryptoKit
import Security

enum RSAError: Error {
    case keyGenerationFailed, encryptionFailed, decryptionFailed
    case invalidKeySize, invalidMessage, invalidCiphertext
    case fileReadFailed, fileWriteFailed, invalidPublicKey
    case wienerAttackFailed, weakKeyDetected
}

actor RSAKeyGenerator {
    private let minKeySize = 2048
    private let wienerThreshold = 1024
    
    struct KeyPair {
        let publicKey: SecKey
        let privateKey: SecKey
        let n: Data
        let e: Data
        let d: Data
    }
    
    func generateKeyPair(keySize: Int = 2048,
                        publicExponent: UInt = 65537) throws -> KeyPair {
        guard keySize >= minKeySize else { throw RSAError.invalidKeySize }
        
        var attempts = 0
        while attempts < 100 {
            do {
                let keys = try generateSafeKeys(keySize: keySize,
                                               publicExponent: publicExponent)
                
                if try !isVulnerableToWiener(n: keys.n, e: keys.e, d: keys.d) {
                    return keys
                }
                attempts += 1
            } catch {
                attempts += 1
            }
        }
        
        throw RSAError.keyGenerationFailed
    }
    
    private func generateSafeKeys(keySize: Int, publicExponent: UInt) throws -> KeyPair {
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ],
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw RSAError.keyGenerationFailed
        }
        
        let keyData = try exportKeyComponents(privateKey: privateKey)
        
        return KeyPair(
            publicKey: publicKey,
            privateKey: privateKey,
            n: keyData.n,
            e: keyData.e,
            d: keyData.d
        )
    }
    
    private func exportKeyComponents(privateKey: SecKey) throws -> (n: Data, e: Data, d: Data) {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw RSAError.keyGenerationFailed
        }
        
        let keySize = keyData.count
        let nStart = 8
        let nSize = keySize / 2 - 4
        let n = keyData.subdata(in: nStart..<nStart + nSize)
        
        let eStart = nStart + nSize + 4
        let eSize = 3
        let e = keyData.subdata(in: eStart..<eStart + eSize)
        
        let dStart = eStart + eSize + 4
        let dSize = nSize
        let d = keyData.subdata(in: dStart..<dStart + dSize)
        
        return (n, e, d)
    }
    
    private func isVulnerableToWiener(n: Data, e: Data, d: Data) throws -> Bool {
        let nBigInt = BigInt(data: n)
        let dBigInt = BigInt(data: d)
        let quarterRoot = try nBigInt.nthRoot(4)
        let threshold = quarterRoot / 3
        return dBigInt < threshold
    }
}

struct BigInt {
    private var data: Data
    
    init(data: Data) {
        self.data = data
    }
    
    func nthRoot(_ n: Int) throws -> BigInt {
        var result = self
        for _ in 0..<n { }
        return result
    }
    
    static func /(lhs: BigInt, rhs: Int) -> BigInt {
        return lhs
    }
    
    static func <(lhs: BigInt, rhs: BigInt) -> Bool {
        return lhs.data.count < rhs.data.count ||
               (lhs.data.count == rhs.data.count && lhs.data.lexicographicallyPrecedes(rhs.data))
    }
}

class RSA {
    private let keyPair: RSAKeyGenerator.KeyPair
    
    init(keyPair: RSAKeyGenerator.KeyPair) {
        self.keyPair = keyPair
    }
    
    func encrypt(_ data: Data) throws -> Data {
        let blockSize = SecKeyGetBlockSize(keyPair.publicKey)
        var encryptedData = Data()
        
        for i in stride(from: 0, to: data.count, by: blockSize - 11) {
            let chunk = data.subdata(in: i..<min(i + blockSize - 11, data.count))
            var error: Unmanaged<CFError>?
            
            guard let encryptedChunk = SecKeyCreateEncryptedData(
                keyPair.publicKey,
                .rsaEncryptionPKCS1,
                chunk as CFData,
                &error
            ) as Data? else {
                throw RSAError.encryptionFailed
            }
            
            encryptedData.append(encryptedChunk)
        }
        
        return encryptedData
    }
    
    func decrypt(_ data: Data) throws -> Data {
        let blockSize = SecKeyGetBlockSize(keyPair.privateKey)
        var decryptedData = Data()
        
        for i in stride(from: 0, to: data.count, by: blockSize) {
            let chunk = data.subdata(in: i..<min(i + blockSize, data.count))
            var error: Unmanaged<CFError>?
            
            guard let decryptedChunk = SecKeyCreateDecryptedData(
                keyPair.privateKey,
                .rsaEncryptionPKCS1,
                chunk as CFData,
                &error
            ) as Data? else {
                throw RSAError.decryptionFailed
            }
            
            decryptedData.append(decryptedChunk)
        }
        
        return decryptedData
    }
    
    func encryptString(_ text: String) throws -> Data {
        guard let data = text.data(using: .utf8) else {
            throw RSAError.invalidMessage
        }
        return try encrypt(data)
    }
    
    func decryptString(_ data: Data) throws -> String {
        let decrypted = try decrypt(data)
        guard let text = String(data: decrypted, encoding: .utf8) else {
            throw RSAError.invalidCiphertext
        }
        return text
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

actor AsyncFileRSA {
    private let rsa: RSA
    private let chunkSize: Int
    
    init(rsa: RSA, chunkSize: Int = 256) {
        self.rsa = rsa
        self.chunkSize = chunkSize
    }
    
    func encryptFile(at inputURL: URL, to outputURL: URL) async throws {
        try await processFile(inputURL: inputURL, outputURL: outputURL, encrypt: true)
    }
    
    func decryptFile(at inputURL: URL, to outputURL: URL) async throws {
        try await processFile(inputURL: inputURL, outputURL: outputURL, encrypt: false)
    }
    
    private func processFile(inputURL: URL, outputURL: URL, encrypt: Bool) async throws {
        let handle = try FileHandle(forReadingFrom: inputURL)
        defer { try? handle.close() }
        
        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
        }
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outputHandle = try FileHandle(forWritingTo: outputURL)
        defer { try? outputHandle.close() }
        
        let totalSize = try handle.seekToEnd()
        try handle.seek(toOffset: 0)
        
        let numberOfChunks = Int((totalSize + UInt64(chunkSize) - 1) / UInt64(chunkSize))
        
        try await withThrowingTaskGroup(of: (Int, Data).self) { group in
            for chunkIndex in 0..<numberOfChunks {
                group.addTask {
                    let offset = UInt64(chunkIndex * self.chunkSize)
                    try handle.seek(toOffset: offset)
                    let chunk = handle.readData(ofLength: self.chunkSize)
                    
                    let processed = try await Task.detached {
                        if encrypt {
                            return try self.rsa.encrypt(chunk)
                        } else {
                            return try self.rsa.decrypt(chunk)
                        }
                    }.value
                    
                    return (chunkIndex, processed)
                }
            }
            
            var results = Array(repeating: Data?.none, count: numberOfChunks)
            for try await (index, data) in group {
                results[index] = data
            }
            
            for case let data? in results {
                try outputHandle.write(contentsOf: data)
            }
        }
    }
    
    func processMultipleFiles(files: [(input: URL, output: URL)], encrypt: Bool) async throws {
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

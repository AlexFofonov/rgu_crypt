import Foundation
import CryptoKit
import CommonCrypto

enum CryptoError: Error {
    case invalidKeySize, invalidBlockSize, invalidIV, fileReadFailed, fileWriteFailed
    case encryptionFailed, decryptionFailed, paddingError, unsupportedAlgorithm
}

enum Padding {
    case zeros, ansiX923, pkcs7, iso10126
}

enum BlockMode {
    case ecb, cbc, pcbc, cfb, ofb, ctr, randomDelta
}

protocol BlockCipher {
    var blockSize: Int { get }
    func encrypt(block: Data, key: Data) throws -> Data
    func decrypt(block: Data, key: Data) throws -> Data
}

struct DES: BlockCipher {
    let blockSize = 8
    
    func encrypt(block: Data, key: Data) throws -> Data {
        guard key.count == 8 else { throw CryptoError.invalidKeySize }
        var encrypted = Data(count: blockSize)
        try encrypted.withUnsafeMutableBytes { encryptedBytes in
            try block.withUnsafeBytes { plainBytes in
                try key.withUnsafeBytes { keyBytes in
                    var cryptor: CCCryptorRef?
                    let status = CCCryptorCreate(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmDES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress,
                        kCCKeySizeDES,
                        nil,
                        &cryptor
                    )
                    guard status == kCCSuccess else { throw CryptoError.encryptionFailed }
                    
                    var dataOutMoved = 0
                    let updateStatus = CCCryptorUpdate(
                        cryptor,
                        plainBytes.baseAddress,
                        blockSize,
                        encryptedBytes.baseAddress,
                        blockSize,
                        &dataOutMoved
                    )
                    CCCryptorRelease(cryptor)
                    guard updateStatus == kCCSuccess else { throw CryptoError.encryptionFailed }
                }
            }
        }
        return encrypted
    }
    
    func decrypt(block: Data, key: Data) throws -> Data {
        guard key.count == 8 else { throw CryptoError.invalidKeySize }
        var decrypted = Data(count: blockSize)
        try decrypted.withUnsafeMutableBytes { decryptedBytes in
            try block.withUnsafeBytes { cipherBytes in
                try key.withUnsafeBytes { keyBytes in
                    var cryptor: CCCryptorRef?
                    let status = CCCryptorCreate(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmDES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress,
                        kCCKeySizeDES,
                        nil,
                        &cryptor
                    )
                    guard status == kCCSuccess else { throw CryptoError.decryptionFailed }
                    
                    var dataOutMoved = 0
                    let updateStatus = CCCryptorUpdate(
                        cryptor,
                        cipherBytes.baseAddress,
                        blockSize,
                        decryptedBytes.baseAddress,
                        blockSize,
                        &dataOutMoved
                    )
                    CCCryptorRelease(cryptor)
                    guard updateStatus == kCCSuccess else { throw CryptoError.decryptionFailed }
                }
            }
        }
        return decrypted
    }
}

struct TripleDES: BlockCipher {
    let blockSize = 8
    
    func encrypt(block: Data, key: Data) throws -> Data {
        guard key.count == 24 else { throw CryptoError.invalidKeySize }
        var encrypted = Data(count: blockSize)
        let status = encrypted.withUnsafeMutableBytes { encryptedBytes in
            block.withUnsafeBytes { plainBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithm3DES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress,
                        kCCKeySize3DES,
                        nil,
                        plainBytes.baseAddress,
                        blockSize,
                        encryptedBytes.baseAddress,
                        blockSize,
                        nil
                    )
                }
            }
        }
        return status == kCCSuccess ? encrypted : throw CryptoError.encryptionFailed
    }
    
    func decrypt(block: Data, key: Data) throws -> Data {
        guard key.count == 24 else { throw CryptoError.invalidKeySize }
        var decrypted = Data(count: blockSize)
        let status = decrypted.withUnsafeMutableBytes { decryptedBytes in
            block.withUnsafeBytes { cipherBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithm3DES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress,
                        kCCKeySize3DES,
                        nil,
                        cipherBytes.baseAddress,
                        blockSize,
                        decryptedBytes.baseAddress,
                        blockSize,
                        nil
                    )
                }
            }
        }
        return status == kCCSuccess ? decrypted : throw CryptoError.decryptionFailed
    }
}

struct DEAL: BlockCipher {
    let blockSize = 16
    private let des = DES()
    
    func encrypt(block: Data, key: Data) throws -> Data {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw CryptoError.invalidKeySize
        }
        var result = block
        for i in stride(from: 0, to: key.count, by: 8) {
            let subkey = key.subdata(in: i..<min(i+8, key.count))
            result = try processBlock(result, key: subkey, encrypt: true)
        }
        return result
    }
    
    func decrypt(block: Data, key: Data) throws -> Data {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw CryptoError.invalidKeySize
        }
        var result = block
        for i in stride(from: key.count-8, through: 0, by: -8) {
            let subkey = key.subdata(in: i..<i+8)
            result = try processBlock(result, key: subkey, encrypt: false)
        }
        return result
    }
    
    private func processBlock(_ block: Data, key: Data, encrypt: Bool) throws -> Data {
        let left = block.prefix(8)
        let right = block.suffix(8)
        
        let processedRight = try encrypt ? des.encrypt(block: right, key: key)
                                          : des.decrypt(block: right, key: key)
        
        let newLeft = right
        let newRight = xor(left, processedRight)
        
        return newLeft + newRight
    }
    
    private func xor(_ a: Data, _ b: Data) -> Data {
        return Data(zip(a, b).map { $0 ^ $1 })
    }
}

class CryptoProcessor {
    private let cipher: BlockCipher
    private let mode: BlockMode
    private let padding: Padding
    private let iv: Data?
    
    init(cipher: BlockCipher, mode: BlockMode, padding: Padding, iv: Data? = nil) {
        self.cipher = cipher
        self.mode = mode
        self.padding = padding
        self.iv = iv
    }
    
    func encrypt(data: Data, key: Data) throws -> Data {
        var paddedData = try applyPadding(data, blockSize: cipher.blockSize)
        var result = Data()
        
        switch mode {
        case .ecb:
            result = try ecbEncrypt(paddedData, key: key)
        case .cbc:
            result = try cbcEncrypt(paddedData, key: key)
        default:
            throw CryptoError.unsupportedAlgorithm
        }
        
        return result
    }
    
    func decrypt(data: Data, key: Data) throws -> Data {
        var decrypted = Data()
        
        switch mode {
        case .ecb:
            decrypted = try ecbDecrypt(data, key: key)
        case .cbc:
            decrypted = try cbcDecrypt(data, key: key)
        default:
            throw CryptoError.unsupportedAlgorithm
        }
        
        return try removePadding(decrypted)
    }
    
    private func ecbEncrypt(_ data: Data, key: Data) throws -> Data {
        var encrypted = Data()
        for i in stride(from: 0, to: data.count, by: cipher.blockSize) {
            let block = data.subdata(in: i..<i+cipher.blockSize)
            encrypted += try cipher.encrypt(block: block, key: key)
        }
        return encrypted
    }
    
    private func cbcEncrypt(_ data: Data, key: Data) throws -> Data {
        guard let iv = iv, iv.count == cipher.blockSize else {
            throw CryptoError.invalidIV
        }
        
        var encrypted = Data()
        var previousBlock = iv
        
        for i in stride(from: 0, to: data.count, by: cipher.blockSize) {
            let block = data.subdata(in: i..<i+cipher.blockSize)
            let xored = xor(block, previousBlock)
            let cipherBlock = try cipher.encrypt(block: xored, key: key)
            encrypted += cipherBlock
            previousBlock = cipherBlock
        }
        
        return encrypted
    }
    
    private func ecbDecrypt(_ data: Data, key: Data) throws -> Data {
        var decrypted = Data()
        for i in stride(from: 0, to: data.count, by: cipher.blockSize) {
            let block = data.subdata(in: i..<i+cipher.blockSize)
            decrypted += try cipher.decrypt(block: block, key: key)
        }
        return decrypted
    }
    
    private func cbcDecrypt(_ data: Data, key: Data) throws -> Data {
        guard let iv = iv, iv.count == cipher.blockSize else {
            throw CryptoError.invalidIV
        }
        
        var decrypted = Data()
        var previousBlock = iv
        
        for i in stride(from: 0, to: data.count, by: cipher.blockSize) {
            let block = data.subdata(in: i..<i+cipher.blockSize)
            let decryptedBlock = try cipher.decrypt(block: block, key: key)
            let plain = xor(decryptedBlock, previousBlock)
            decrypted += plain
            previousBlock = block
        }
        
        return decrypted
    }
    
    private func applyPadding(_ data: Data, blockSize: Int) throws -> Data {
        let paddingLength = blockSize - (data.count % blockSize)
        var padded = data
        
        switch padding {
        case .zeros:
            padded.append(Data(repeating: 0, count: paddingLength))
        case .pkcs7:
            let byte = UInt8(paddingLength)
            padded.append(Data(repeating: byte, count: paddingLength))
        case .ansiX923:
            padded.append(Data(repeating: 0, count: paddingLength - 1))
            padded.append(UInt8(paddingLength))
        case .iso10126:
            var randomBytes = Data(count: paddingLength - 1)
            randomBytes.withUnsafeMutableBytes { bytes in
                arc4random_buf(bytes.baseAddress, paddingLength - 1)
            }
            padded.append(randomBytes)
            padded.append(UInt8(paddingLength))
        }
        
        return padded
    }
    
    private func removePadding(_ data: Data) throws -> Data {
        guard let lastByte = data.last else { return data }
        
        switch padding {
        case .zeros:
            let paddingStart = data.count - Int(lastByte)
            return data.prefix(paddingStart)
        case .pkcs7, .ansiX923, .iso10126:
            let paddingLength = Int(lastByte)
            guard paddingLength > 0 && paddingLength <= cipher.blockSize else {
                throw CryptoError.paddingError
            }
            return data.prefix(data.count - paddingLength)
        }
    }
    
    private func xor(_ a: Data, _ b: Data) -> Data {
        return Data(zip(a, b).map { $0 ^ $1 })
    }
}

actor FileCryptoManager {
    private let processor: CryptoProcessor
    
    init(processor: CryptoProcessor) {
        self.processor = processor
    }
    
    func encryptFile(at inputURL: URL,
                    to outputURL: URL,
                    key: Data) async throws {
        let data = try Data(contentsOf: inputURL)
        let encrypted = try processor.encrypt(data: data, key: key)
        try encrypted.write(to: outputURL)
    }
    
    func decryptFile(at inputURL: URL,
                    to outputURL: URL,
                    key: Data) async throws {
        let data = try Data(contentsOf: inputURL)
        let decrypted = try processor.decrypt(data: data, key: key)
        try decrypted.write(to: outputURL)
    }
    
    func processConcurrently(files: [(URL, URL)],
                           key: Data,
                           encrypt: Bool) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (input, output) in files {
                group.addTask {
                    if encrypt {
                        try await self.encryptFile(at: input, to: output, key: key)
                    } else {
                        try await self.decryptFile(at: input, to: output, key: key)
                    }
                }
            }
            try await group.waitForAll()
        }
    }
}

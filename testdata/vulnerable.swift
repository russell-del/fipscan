import CommonCrypto
import CryptoKit
import Foundation

func badMD5(data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
    return Data(digest)
}

func badSHA1(data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    _ = data.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest) }
    return Data(digest)
}

func badMD5Kit(data: Data) -> Insecure.MD5.Digest {
    return Insecure.MD5.hash(data: data)
}

func badSHA1Kit(data: Data) -> Insecure.SHA1.Digest {
    return Insecure.SHA1.hash(data: data)
}

let desAlgo = kCCAlgorithmDES
let tripleDesAlgo = kCCAlgorithm3DES
let rc4Algo = kCCAlgorithmRC4

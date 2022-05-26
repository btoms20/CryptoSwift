//
//  CryptoSwift
//
//  Copyright (C) 2014-2021 Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  In no event will the authors be held liable for any damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
//
//  - The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
//  - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
//  - This notice may not be removed or altered from any source or binary distribution.
//

// Foundation is required for `Data` to be found
import Foundation

// Note: The `BigUInt` struct was copied from:
// https://github.com/attaswift/BigInt
// It allows fast calculation for RSA big numbers

public final class RSA {
  
  public enum Error: Swift.Error {
    /// No private key specified
    case noPrivateKey
    case invalidSignatureLength
  }
  
  /// RSA Modulus
  public let n: BigUInteger
  
  /// RSA Public Exponent
  public let e: BigUInteger
  
  /// RSA Private Exponent
  public let d: BigUInteger?
  
  /// The size of the modulus, in bits
  public let keySize: Int
  
  /// Initialize with RSA parameters
  /// - Parameters:
  ///   - n: The RSA Modulus
  ///   - e: The RSA Public Exponent
  ///   - d: The RSA Private Exponent (or nil if unknown, e.g. if only public key is known)
  public init(n: BigUInteger, e: BigUInteger, d: BigUInteger? = nil) {
    self.n = n
    self.e = e
    self.d = d
    
    self.keySize = n.bitWidth
  }
  
  /// Initialize with RSA parameters
  /// - Parameters:
  ///   - n: The RSA Modulus
  ///   - e: The RSA Public Exponent
  ///   - d: The RSA Private Exponent (or nil if unknown, e.g. if only public key is known)
  public convenience init(n: Array<UInt8>, e: Array<UInt8>, d: Array<UInt8>? = nil) {
    if let d = d {
      self.init(n: BigUInteger(Data(n)), e: BigUInteger(Data(e)), d: BigUInteger(Data(d)))
    } else {
      self.init(n: BigUInteger(Data(n)), e: BigUInteger(Data(e)))
    }
  }
  
  /// Initialize with a generated key pair
  /// - Parameter keySize: The size of the modulus
  public convenience init(keySize: Int) {
    // Generate prime numbers
    let p = BigUInteger.generatePrime(keySize / 2)
    let q = BigUInteger.generatePrime(keySize / 2)
    
    // Calculate modulus
    let n = p * q
    
    // Calculate public and private exponent
    let e: BigUInteger = 65537
    let phi = (p - 1) * (q - 1)
    let d = e.inverse(phi)
    
    // Initialize
    self.init(n: n, e: e, d: d)
  }
  
  // TODO: Add initializer from PEM (ASN.1 with DER header) (See #892)
  
  // TODO: Add export to PEM (ASN.1 with DER header) (See #892)
  
}

// MARK: Cipher

extension RSA: Cipher {
  
  @inlinable
  public func encrypt(_ bytes: ArraySlice<UInt8>) throws -> Array<UInt8> {
    // Calculate encrypted data
    return BigUInteger(Data(bytes)).power(e, modulus: n).serialize().bytes
  }

  @inlinable
  public func decrypt(_ bytes: ArraySlice<UInt8>) throws -> Array<UInt8> {
    // Check for Private Exponent presence
    guard let d = d else {
      throw RSA.Error.noPrivateKey
    }
    
    // Calculate decrypted data
    return BigUInteger(Data(bytes)).power(d, modulus: n).serialize().bytes
  }
  
}

// MARK: CS.BigUInt extension

extension BigUInteger {
  
  public static func generatePrime(_ width: Int) -> BigUInteger {
    // Note: Need to find a better way to generate prime numbers
    while true {
      var random = BigUInteger.randomInteger(withExactWidth: width)
      random |= BigUInteger(1)
      if random.isPrime() {
        return random
      }
    }
  }
  
}

// MARK: Signatures & Verification
extension RSA {
  public enum SignatureVariant {
    case pkcs1v15_MD5
    case pkcs1v15_SHA1
    case pkcs1v15_SHA224
    case pkcs1v15_SHA256
    case pkcs1v15_SHA384
    case pkcs1v15_SHA512
    case pkcs1v15_SHA512_224
    case pkcs1v15_SHA512_256

    var identifier:Array<UInt8> {
      switch self {
      case .pkcs1v15_MD5       : return Array<UInt8>(arrayLiteral: 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05)
      case .pkcs1v15_SHA1      : return Array<UInt8>(arrayLiteral: 0x2b, 0x0e, 0x03, 0x02, 0x1a)
      case .pkcs1v15_SHA224    : return Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04)
      case .pkcs1v15_SHA256    : return Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
      case .pkcs1v15_SHA384    : return Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)
      case .pkcs1v15_SHA512    : return Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)
      case .pkcs1v15_SHA512_224: return Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05)
      case .pkcs1v15_SHA512_256: return Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06)
      }
    }
    
    func calculateHash(_ bytes: Array<UInt8>) -> Array<UInt8> {
      switch self {
      case .pkcs1v15_MD5:
      return Digest.md5(bytes)
      case .pkcs1v15_SHA1:
      return Digest.sha1(bytes)
      case .pkcs1v15_SHA224:
      return Digest.sha224(bytes)
      case .pkcs1v15_SHA256:
      return Digest.sha256(bytes)
      case .pkcs1v15_SHA384:
      return Digest.sha384(bytes)
      case .pkcs1v15_SHA512:
      return Digest.sha512(bytes)
      case .pkcs1v15_SHA512_224:
      return Digest.sha2(bytes, variant: .sha224)
      case .pkcs1v15_SHA512_256:
          return Digest.sha2(bytes, variant: .sha256)
      }
    }
    
    /// Right now the only Padding Scheme supported is [EMCS-PKCS1v15](https://www.rfc-editor.org/rfc/rfc8017#section-9.2) (others include [EMSA-PSS](https://www.rfc-editor.org/rfc/rfc8017#section-9.1))
    func pad(bytes: Array<UInt8>, to blockSize:Int) -> Array<UInt8> {
      return Padding.pkcs1v15.add(to: bytes, blockSize: blockSize)
    }
  }
  
  //public func sign(_ bytes: Array<UInt8>, padding padder: Padding = .pkcs1v15, hashedWith hashFunc:HashVariant) throws -> Array<UInt8> {
  public func sign(_ bytes: Array<UInt8>, variant:SignatureVariant = .pkcs1v15_SHA256) throws -> Array<UInt8> {
    // Check for Private Exponent presence
    guard let d = d else {
      throw RSA.Error.noPrivateKey
    }
        
    // Hash & Encode Message
    let hashedAndEncoded = try RSA.hashedAndEncoded(bytes, variant: variant, keySize: keySize / 8)
        
    /// Calculate the Signature
    let signedData = BigUInteger(Data(hashedAndEncoded)).power(d, modulus: n).serialize().bytes
        
    return signedData
  }

  //public func verify(signature: Array<UInt8>, for bytes: Array<UInt8>, padding padder:Padding = .pkcs1v15, hashedWith hashFunc:HashVariant) throws -> Bool {
  public func verify(signature: Array<UInt8>, for bytes: Array<UInt8>, variant:SignatureVariant = .pkcs1v15_SHA256) throws -> Bool {
    /// Step 1: Ensure the signature is the same length as the key's modulus
    guard signature.count == keySize else { throw Error.invalidSignatureLength }
      
    let expectedData = try Array<UInt8>(RSA.hashedAndEncoded(bytes, variant: variant, keySize: keySize / 8).dropFirst())
    
    /// Step 2: 'Decrypt' the signature
    let signatureResult = BigUInteger(Data(signature)).power(e, modulus: n).serialize().bytes
      
    /// Step 3: Compare the 'decrypted' signature with the prepared / encoded expected message....
    guard signatureResult == expectedData else { return false }
      
    return true
  }
  
  /// Hashes and Encodes a message for signing and verifying
  ///
  /// - Note: [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2)
  fileprivate static func hashedAndEncoded(_ bytes:[UInt8], variant:SignatureVariant, keySize:Int) throws -> Array<UInt8> {
    /// 1.  Apply the hash function to the message M to produce a hash
    let hashedMessage = variant.calculateHash(bytes)
        
    /// 2. Encode the algorithm ID for the hash function and the hash value into an ASN.1 value of type DigestInfo
    /// PKCS#1_15 DER Structure (OID == sha256WithRSAEncryption)
    let asn:ASN1.Parser.Node = .sequence(nodes: [
      .sequence(nodes: [
        .objectIdentifier(data: Data(variant.identifier)),
        .null
      ]),
      .octetString(data: Data(hashedMessage))
    ])
        
    let t = ASN1.Encoder.encode(asn)
        
    /// 3.  If emLen < tLen + 11, output "intended encoded message lengthtoo short" and stop
    if keySize < t.count + 11 { throw NSError(domain: "intended encoded message length too short", code: 0) }
        
    /// 4.  Generate an octet string PS consisting of emLen - tLen - 3
    /// octets with hexadecimal value 0xff. The length of PS will be
    /// at least 8 octets.
      let padded = variant.pad(bytes: t, to: keySize)
        
    guard padded.count == keySize else { throw NSError(domain: "intended encoded message length too short", code: 0) }
        
    /// 5.  Concatenate PS, the DER encoding T, and other padding to form
    /// the encoded message EM as EM = 0x00 || 0x01 || PS || 0x00 || T.
    print(padded.toHexString())
    return padded
  }
}

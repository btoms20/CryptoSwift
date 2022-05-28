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

public final class RSA:DERCodable {
  /// RSA Object Identifier Bytes (rsaEncryption)
  internal static var objectIdentifier = Array<UInt8>(arrayLiteral: 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)
    
  public enum Error: Swift.Error {
    /// No private key specified
    case noPrivateKey
    /// We were provided invalid DER data
    case invalidDERFormat
    /// Failed to verify primes during DER initialiization (the provided primes don't reproduce the provided private exponent)
    case invalidPrimes
    /// We attempted to export a private key without our underlying primes
    case noPrimes
    /// Unable to calculate the coefficient during a private key DER export
    case unableToCalculateCoefficient
  }
  
  /// RSA Modulus
  public let n: BigUInteger
  
  /// RSA Public Exponent
  public let e: BigUInteger
  
  /// RSA Private Exponent
  public let d: BigUInteger?
  
  /// The size of the modulus, in bits
  public let keySize: Int
  
  /// The underlying primes used to generate the Private Exponent
  private let primes:(p:BigUInteger, q:BigUInteger)?
  
  /// Initialize with RSA parameters
  /// - Parameters:
  ///   - n: The RSA Modulus
  ///   - e: The RSA Public Exponent
  ///   - d: The RSA Private Exponent (or nil if unknown, e.g. if only public key is known)
  public init(n: BigUInteger, e: BigUInteger, d: BigUInteger? = nil) {
    self.n = n
    self.e = e
    self.d = d
    self.primes = nil
    
    self.keySize = n.bitWidth
  }
  
  /// Initialize with RSA parameters
  /// - Parameters:
  ///   - n: The RSA Modulus
  ///   - e: The RSA Public Exponent
  ///   - d: The RSA Private Exponent
  ///   - p: The 1st Prime used to generate the Private Exponent
  ///   - q: The 2nd Prime used to generate the Private Exponent
  private init(n: BigUInteger, e: BigUInteger, d: BigUInteger, p: BigUInteger, q: BigUInteger) {
    self.n = n
    self.e = e
    self.d = d
    self.primes = (p, q)
  
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
    self.init(n: n, e: e, d: d!, p: p, q: q)
  }
    
  /// Partially overrides the auto generated PEM initializer
  /// - Parameters:
  ///   - pem: the PEM string representing your RSA key
  ///   - password: An optional password if the PEM you're importing happens to be encrypted / password protected
  ///   - Note: This is a silly hack that helps the compiler determine the Key type on our generic init
  public convenience init(pem:String, password:String? = nil) throws {
    try self.init(pem: pem, password: password, asType: RSA.self)
  }

  /// Partially overrides the auto generated PEM initializer
  /// - Parameters:
  ///   - pem: the PEM string representing your RSA key
  ///   - password: An optional password if the PEM you're importing happens to be encrypted / password protected
  ///   - Note: This is a silly hack that helps the compiler determine the Key type on our generic init
  public convenience init(pem:Data, password:String? = nil) throws {
    try self.init(pem: pem, password: password, asType: RSA.self)
  }
}

// MARK: DER Initializers (See #892)

extension RSA {
  /// Decodes the provided data into a Public RSA Key
  ///
  /// ```
  /// RSAPublicKey ::= SEQUENCE {
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER,  -- e
  /// }
  /// ```
  internal convenience init(publicDER der: Array<UInt8>) throws {
    let asn = try ASN1.Parser.parse(data: Data(der))
    
    // Enforce the above ASN Structure
    guard case .sequence(let params) = asn else { throw Error.invalidDERFormat }
    guard params.count == 2 else { throw Error.invalidDERFormat }
  
    guard case .integer(let modulus)         = params[0] else { throw Error.invalidDERFormat }
    guard case .integer(let publicExponent)  = params[1] else { throw Error.invalidDERFormat }
  
    self.init(n: BigUInteger(modulus), e: BigUInteger(publicExponent))
  }
    
  /// Decodes the provided data into a Private RSA Key
  ///
  /// ```
  /// RSAPrivateKey ::= SEQUENCE {
  ///   version           Version,
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER,  -- e
  ///   privateExponent   INTEGER,  -- d
  ///   prime1            INTEGER,  -- p
  ///   prime2            INTEGER,  -- q
  ///   exponent1         INTEGER,  -- d mod (p-1)
  ///   exponent2         INTEGER,  -- d mod (q-1)
  ///   coefficient       INTEGER,  -- (inverse of q) mod p
  ///   otherPrimeInfos   OtherPrimeInfos OPTIONAL
  /// }
  /// ```
  internal convenience init(privateDER der: Array<UInt8>) throws {
    let asn = try ASN1.Parser.parse(data: Data(der))
  
    // Enforce the above ASN Structure (do we need to extract and verify the eponents and coefficients?)
    guard case .sequence(let params) = asn else { throw Error.invalidDERFormat }
    guard params.count >= 9 else { throw Error.invalidDERFormat }
    guard case .integer(let version)         = params[0] else { throw Error.invalidDERFormat }
    guard case .integer(let modulus)         = params[1] else { throw Error.invalidDERFormat }
    guard case .integer(let publicExponent)  = params[2] else { throw Error.invalidDERFormat }
    guard case .integer(let privateExponent) = params[3] else { throw Error.invalidDERFormat }
    guard case .integer(let prime1)          = params[4] else { throw Error.invalidDERFormat }
    guard case .integer(let prime2)          = params[5] else { throw Error.invalidDERFormat }
    guard case .integer(let exponent1)       = params[6] else { throw Error.invalidDERFormat }
    guard case .integer(let exponent2)       = params[7] else { throw Error.invalidDERFormat }
    guard case .integer(let coefficient)     = params[8] else { throw Error.invalidDERFormat }
    
    // Are there other versions out there? Is this even the version? 
    guard version == Data(hex: "0x00") else { throw Error.invalidDERFormat }
    
    // Ensure the supplied parameters are correct...
    // Calculate modulus
    guard BigUInteger(modulus) == BigUInteger(prime1) * BigUInteger(prime2) else { throw Error.invalidPrimes }
      
    // Calculate public and private exponent
    let phi = (BigUInteger(prime1) - 1) * (BigUInteger(prime2) - 1)
    guard let d = BigUInteger(publicExponent).inverse(phi) else { throw Error.invalidPrimes }
    guard BigUInteger(privateExponent) == d else { throw Error.invalidPrimes }
     
    // Ensure the provided coefficient is correct (derived from the primes)
    // - Note: this might be overkill, cause we don't store the coefficient, but the extra check probably isn't the worse thing
    guard let calculatedCoefficient = BigUInteger(prime2).inverse(BigUInteger(prime1)) else { throw RSA.Error.unableToCalculateCoefficient }
    guard calculatedCoefficient == BigUInteger(coefficient) else { throw RSA.Error.invalidPrimes }
    
    // Ensure the provided exponents are correct as well
    // - Note: this might be overkill, cause we don't store them, but the extra check probably isn't the worse thing
    guard (d % (BigUInteger(prime1) - 1)) == BigUInteger(exponent1) else { throw RSA.Error.invalidPrimes }
    guard (d % (BigUInteger(prime2) - 1)) == BigUInteger(exponent2) else { throw RSA.Error.invalidPrimes }
    
    // Proceed with regular initialization
    self.init(n: BigUInteger(modulus), e: BigUInteger(publicExponent), d: BigUInteger(privateExponent), p: BigUInteger(prime1), q: BigUInteger(prime2))
  }
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


// MARK: DER Exports (See #892)

extension RSA {
  /// The DER representation of this public key
  ///
  /// ```
  /// =========================
  ///  RSA PublicKey Structure
  /// =========================
  ///
  /// RSAPublicKey ::= SEQUENCE {
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER   -- e
  /// }
  /// ```
  func publicKeyDER() throws -> Array<UInt8> {
    let mod = n.serialize()
    let pubKeyAsnNode:ASN1.Parser.Node =
      .sequence(nodes: [
        .integer(data: DER.i2ospData(x: mod.bytes, size: keySize / 8)),
        .integer(data: DER.i2ospData(x: e.serialize().bytes, size: 3))
    ])
    return ASN1.Encoder.encode(pubKeyAsnNode)
  }
    
    
  /// The PEM representation of this private key
  ///
  /// ```
  /// ==========================
  ///  RSA PrivateKey Structure
  /// ==========================
  ///
  /// RSAPrivateKey ::= SEQUENCE {
  ///   version           Version,
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER,  -- e
  ///   privateExponent   INTEGER,  -- d
  ///   prime1            INTEGER,  -- p
  ///   prime2            INTEGER,  -- q
  ///   exponent1         INTEGER,  -- d mod (p-1)
  ///   exponent2         INTEGER,  -- d mod (q-1)
  ///   coefficient       INTEGER,  -- (inverse of q) mod p
  ///   otherPrimeInfos   OtherPrimeInfos OPTIONAL
  /// }
  /// ```
  func privateKeyDER() throws -> Array<UInt8> {
    // Make sure we have a private key
    guard let d = d else { throw RSA.Error.noPrivateKey }
    // Make sure we have access to our primes
    guard let primes = primes else { throw RSA.Error.noPrimes }
    // Make sure we can calculate our coefficient (inverse of q mod p)
    guard let coefficient = primes.q.inverse(primes.p) else { throw RSA.Error.unableToCalculateCoefficient }
  
    let bitWidth = keySize / 8
    let paramWidth = bitWidth / 2
    // Structure the data
    let mod = n.serialize()
    let privateKeyAsnNode:ASN1.Parser.Node =
      .sequence(nodes: [
        .integer(data: Data(hex: "0x00")),
        .integer(data: DER.i2ospData(x: mod.bytes, size: bitWidth)),
        .integer(data: DER.i2ospData(x: e.serialize().bytes, size: 3)),
        .integer(data: DER.i2ospData(x: d.serialize().bytes, size: bitWidth)),
        .integer(data: DER.i2ospData(x: primes.p.serialize().bytes, size: paramWidth)),
        .integer(data: DER.i2ospData(x: primes.q.serialize().bytes, size: paramWidth)),
        .integer(data: DER.i2ospData(x: (d % (primes.p - 1)).serialize().bytes, size: paramWidth)),
        .integer(data: DER.i2ospData(x: (d % (primes.q - 1)).serialize().bytes, size: paramWidth)),
        .integer(data: DER.i2ospData(x: coefficient.serialize().bytes, size: paramWidth))
      ])
  
    // Encode and return the data
    return ASN1.Encoder.encode(privateKeyAsnNode)
  }
}


// MARK: CustomStringConvertible Conformance

extension RSA:CustomStringConvertible {
    public var description: String {
        if d != nil {
            return "CryptoSwift.RSA.PrivateKey<\(self.keySize)>"
        } else {
            return "CryptoSwift.RSA.PublicKey<\(self.keySize)>"
        }
    }
}

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
    case invalidDERFormat
    case invalidPEMFormat
    case invalidPrimes
    case invalidParameters
    case noPrimes
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
  
  /// RSA Object Identifier Bytes (rsaEncryption)
  private static var RSA_OBJECT_IDENTIFIER = Array<UInt8>(arrayLiteral: 42, 134, 72, 134, 247, 13, 1, 1, 1)
    
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
  
  // TODO: Add initializer from PEM (ASN.1 with DER header) (See #892)
  
  // TODO: Add export to PEM (ASN.1 with DER header) (See #892)
  
}

// MARK: DER Initializers
extension RSA {
  public convenience init(der bytes:Array<UInt8>) throws {
    let asnNodes = try ASN1.Parser.parse(data: Data(bytes))
    guard case .sequence(let params) = asnNodes else {
      throw Error.invalidPEMFormat
    }
    print("Attempting to import DER with \(params.count) params")
    print(asnNodes)
    if params.count == 2 {
      try self.init(publicDER: bytes)
    } else if params.count >= 9 {
      try self.init(privateDER: bytes)
    } else {
        throw Error.invalidDERFormat
    }
  }
    
  /// Decodes the provided data into a Public RSA Key
  ///
  /// ```
  /// RSAPublicKey ::= SEQUENCE {
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER,  -- e
  /// }
  /// ```
  private convenience init(publicDER der: Array<UInt8>) throws {
    let asn = try ASN1.Parser.parse(data: Data(der))
  
    print("Public DER")
    print(asn)
  
    // Enforce the above ASN Structure
    guard case .sequence(let params) = asn else { throw Error.invalidDERFormat }
    print("Params: \(params.count)")
    print(params)
    guard params.count == 2 else { throw Error.invalidDERFormat }
  
    guard case .integer(let modulus)         = params[0] else { throw Error.invalidDERFormat }
    guard case .integer(let publicExponent)  = params[1] else { throw Error.invalidDERFormat }
  
    print("Mod: \(modulus)")
    print("PubExp: \(publicExponent)")
  
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
  private convenience init(privateDER der: Array<UInt8>) throws {
    let asn = try ASN1.Parser.parse(data: Data(der))
  
    print("Private DER")
    print(asn)
  
    // Enforce the above ASN Structure
    guard case .sequence(let params) = asn else { throw Error.invalidDERFormat }
    guard params.count >= 9 else { throw Error.invalidDERFormat }
    //guard case .integer(let version)         = params[0] else { throw Error.invalidDERFormat }
    guard case .integer(let modulus)         = params[1] else { throw Error.invalidDERFormat }
    guard case .integer(let publicExponent)  = params[2] else { throw Error.invalidDERFormat }
    guard case .integer(let privateExponent) = params[3] else { throw Error.invalidDERFormat }
    guard case .integer(let prime1)          = params[4] else { throw Error.invalidDERFormat }
    guard case .integer(let prime2)          = params[5] else { throw Error.invalidDERFormat }
    //guard case .integer(let exponent1)       = params[6] else { throw Error.invalidDERFormat }
    //guard case .integer(let exponent2)       = params[7] else { throw Error.invalidDERFormat }
    //guard case .integer(let coefficient)     = params[8] else { throw Error.invalidDERFormat }
  
    // Ensure the supplied parameters are correct...
    // Calculate modulus
    guard BigUInteger(modulus) == BigUInteger(prime1) * BigUInteger(prime2) else { throw Error.invalidPrimes }
  
    // Calculate public and private exponent
    let phi = (BigUInteger(prime1) - 1) * (BigUInteger(prime2) - 1)
    guard let d = BigUInteger(publicExponent).inverse(phi) else { throw Error.invalidPrimes }
    guard BigUInteger(privateExponent) == d else { throw Error.invalidPrimes }
     
    // Proceed with regular initialization
    self.init(n: BigUInteger(modulus), e: BigUInteger(publicExponent), d: BigUInteger(privateExponent), p: BigUInteger(prime1), q: BigUInteger(prime2))
  }
}

// MARK: PEM Initializers
extension RSA {
    
  // TODO: Add initializer from PEM (ASN.1 with DER header) (See #892)
  public convenience init(pem:String, password:String? = nil) throws {
    // Parse the provided PEM string into it's bytes and type
    let (type, data) = try RSA.pemToData(pem)
    print("Type: \(type), Data: \(data.count)")
    // If we we're provided a password, make sure the PEM is in fact encrypted, otherwise throw an error...
    if password != nil { guard type == .encryptedPrivateKey else { throw Error.invalidPEMFormat } }
  
    // Switch over the PEM type and attempt to instantiate our RSA key
    switch type {
    case .publicKeyDER:
        try self.init(der: data)
    case .publicKeyPEM:
        try self.init(publicPEM: data)
    case .privateKey:
        try self.init(privatePEM: data)
    case .encryptedPrivateKey:
        // Parse out Encryption Strategy and CipherText
        let encryptionStategy = try RSA.decodeEncryptedPEM(Data(data))
  
        // Derive Encryption Key from Password
        // PBKDF2-SHA1
        guard let password = password else { throw Error.invalidPEMFormat }
        let key = try PKCS5.PBKDF2(password: password.bytes, salt: encryptionStategy.salt.bytes, iterations: encryptionStategy.iterations, keyLength: 16, variant: .sha1).calculate()
  
        // Decrypt CipherText
        let aes = try AES(key: key, blockMode: CBC(iv: encryptionStategy.iv.bytes), padding: .noPadding)
        let decryptedKey = try aes.decrypt(encryptionStategy.ciphertext.bytes)
  
        // Init from Raw Representation
        print(decryptedKey)
  
        // Proceed with the unencrypted PEM
        try self.init(privatePEM: decryptedKey)
    }
  }
    
  /// Decodes the provided data into a Public RSA Key
  ///
  /// ```
  /// RSAPublicPEM ::= SEQUENCE {
  ///   sequence
  ///     objectIdentifier  rsaEncryption
  ///     null
  ///   bitString           PublicKey DER Representation
  /// }
  /// ```
  private convenience init(publicPEM pem: Array<UInt8>) throws {
    let bits = try RSA.decodePublicPEM(Data(pem))
  
    // Init with the DER data
    try self.init(publicDER: bits.bytes)
  }
  
  /// Decodes the provided data into a Public RSA Key
  ///
  /// ```
  /// RSAPrivatePEM ::= SEQUENCE {
  ///   integer             version
  ///   sequence
  ///     objectIdentifier  rsaEncryption
  ///     null
  ///   octetString         PrivateKey DER Representation
  /// }
  /// ```
  private convenience init(privatePEM pem: Array<UInt8>) throws {
    // Enforce the above ASN Structure
    let octets = try RSA.decodePrivatePEM(Data(pem))
  
    // Init with the DER data
    try self.init(privateDER: octets.bytes)
  }
    
  /// 0:d=0  hl=4 l= 546 cons: SEQUENCE
  /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
  /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
  /// 17:d=2  hl=2 l=   0 prim:   NULL
  /// 19:d=1  hl=4 l= 527 prim:  BIT STRING
  private static func decodePublicPEM(_ pem:Data) throws -> Data {
    let asn = try ASN1.Parser.parse(data: pem)

    print("Public PEM")
    print(asn)
      
    // Enforce the above ASN Structure
    guard case .sequence(let sequence) = asn else { throw Error.invalidPEMFormat }
    guard sequence.count == 2 else { throw Error.invalidPEMFormat }
    guard case .sequence(let params) = sequence.first else { throw Error.invalidPEMFormat }
    guard params.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objectID) = params.first else { throw Error.invalidPEMFormat }
    guard case .null = params.last else { throw Error.invalidPEMFormat }
    guard case .bitString(let bits) = sequence.last else { throw Error.invalidPEMFormat }
  
    // Ensure the ObjectID specified in the PEM is rsaEncryption
    guard objectID.bytes == RSA.RSA_OBJECT_IDENTIFIER else { throw Error.invalidPEMFormat }
  
    return bits
  }
  
  /// 0:d=0  hl=4 l= 630 cons: SEQUENCE
  /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
  /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
  /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
  /// 20:d=2  hl=2 l=   0 prim:   NULL
  /// 22:d=1  hl=4 l= 608 prim:  OCTET STRING      [HEX DUMP]:3082...AA50
  private static func decodePrivatePEM(_ pem:Data) throws -> Data {
    let asn = try ASN1.Parser.parse(data: pem)
  
    print("Private PEM")
    print(asn)
      
    // Enforce the above ASN Structure
    guard case .sequence(let sequence) = asn else { throw Error.invalidPEMFormat }
    guard sequence.count == 3 else { throw Error.invalidPEMFormat }
    guard case .integer(let integer) = sequence[0] else { throw Error.invalidPEMFormat }
    guard case .sequence(let params) = sequence[1] else { throw Error.invalidPEMFormat }
    guard params.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objectID) = params.first else { throw Error.invalidPEMFormat }
    guard case .null = params.last else { throw Error.invalidPEMFormat }
    guard case .octetString(let octet) = sequence[2] else { throw Error.invalidPEMFormat }
  
    // Ensure the ObjectID specified in the PEM is rsaEncryption
    guard objectID.bytes == RSA.RSA_OBJECT_IDENTIFIER else { throw Error.invalidPEMFormat }
    guard integer == Data(hex: "0x00") else { throw Error.invalidPEMFormat }
  
    return octet
  }
    
  internal enum PEMType {
    case publicKeyDER
    case publicKeyPEM
    case privateKey
    case encryptedPrivateKey
  }
  private static func pemToData(_ str:String) throws -> (type: PEMType, bytes: Array<UInt8>) {
    let chunks = str.split(separator: "\n")
    guard chunks.count > 2,
      let f = chunks.first, f.hasPrefix("-----BEGIN"),
      let l = chunks.last, l.hasSuffix("-----") else {
      throw Error.invalidPEMFormat
    }

    let pemType:PEMType
    switch chunks.first {
    case "-----BEGIN RSA PUBLIC KEY-----":
      pemType = .publicKeyDER
    case "-----BEGIN PUBLIC KEY-----":
      pemType = .publicKeyPEM
    case "-----BEGIN PRIVATE KEY-----":
      pemType = .privateKey
    case "-----BEGIN ENCRYPTED PRIVATE KEY-----":
      pemType = .encryptedPrivateKey
    default:
      throw Error.invalidPEMFormat
    }
    
    guard let data = Data(base64Encoded: chunks[1..<chunks.count-1].joined()) else {
      throw Error.invalidPEMFormat
    }
    
    return (type: pemType, bytes: data.bytes)
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


// MARK: DER Exports
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
  func publicKeyExternalRepresentation() -> Array<UInt8> {
    let mod = n.serialize()
    let pubKeyAsnNode:ASN1.Parser.Node =
      .sequence(nodes: [
        .integer(data: Data(RSA.i2osp(n: mod.bytes, size: keySize / 8))),
        .integer(data: Data(RSA.i2osp(n: e.serialize().bytes, size: 3)))
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
  func privateKeyExternalRepresentation() throws -> Array<UInt8> {
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
        .integer(data: Data(RSA.i2osp(n: mod.bytes, size: bitWidth))),
        .integer(data: Data(RSA.i2osp(n: e.serialize().bytes, size: 3))),
        .integer(data: Data(RSA.i2osp(n: d.serialize().bytes, size: bitWidth))),
        .integer(data: Data(RSA.i2osp(n: primes.p.serialize().bytes, size: paramWidth))),
        .integer(data: Data(RSA.i2osp(n: primes.q.serialize().bytes, size: paramWidth))),
        .integer(data: Data(RSA.i2osp(n: (d % (primes.p - 1)).serialize().bytes, size: paramWidth))),
        .integer(data: Data(RSA.i2osp(n: (d % (primes.q - 1)).serialize().bytes, size: paramWidth))),
        .integer(data: Data(RSA.i2osp(n: coefficient.serialize().bytes, size: paramWidth)))
      ])
  
    // Encode and return the data
    return ASN1.Encoder.encode(privateKeyAsnNode)
  }
    
  fileprivate static func i2osp(n:[UInt8], size:Int) -> [UInt8] {
    var modulus = n
    while modulus.count < size {
      modulus.insert(0x00, at: 0)
    }
    if modulus[0] >= 0x80 {
        modulus.insert(0x00, at: 0)
    }
    return modulus
  }
}

// MARK: PEM Exports
extension RSA {
  func exportPublicKeyPEM() throws -> Array<UInt8> {
    let publicDER = self.publicKeyExternalRepresentation()
    let asnNodes:ASN1.Parser.Node = .sequence(nodes: [
      .sequence(nodes: [
        .objectIdentifier(data: Data(RSA.RSA_OBJECT_IDENTIFIER)),
        .null
      ]),
      .bitString(data: Data( publicDER ))
    ])
  
    return ASN1.Encoder.encode(asnNodes)
  }
  
  func exportPublicKeyPEMString() throws -> String {
    let publicPEMData = try exportPublicKeyPEM()
    let header = "-----BEGIN PUBLIC KEY-----\n"
    let footer = "\n-----END PUBLIC KEY-----"
      let base64 = publicPEMData.toBase64().chunks(ofCount: 64).joined(separator: "\n")
  
    return header + base64 + footer
  }
  
  func exportPrivateKeyPEM() throws -> Array<UInt8> {
    let privateDER = try self.privateKeyExternalRepresentation()
    let asnNodes:ASN1.Parser.Node = .sequence(nodes: [
      .integer(data: Data(hex: "0x00")),
      .sequence(nodes: [
        .objectIdentifier(data: Data(RSA.RSA_OBJECT_IDENTIFIER)),
        .null
      ]),
      .octetString(data: Data( privateDER ))
    ])
  
    return ASN1.Encoder.encode(asnNodes)
  }
  
  func exportPrivateKeyPEMString() throws -> String {
    let privatePEMData = try exportPrivateKeyPEM()
    let header = "-----BEGIN PRIVATE KEY-----\n"
    let footer = "\n-----END PRIVATE KEY-----"
    let base64 = privatePEMData.toBase64().chunks(ofCount: 64).joined(separator: "\n")
  
    return header + base64 + footer
  }
}

// MARK: Encrypted PEM
extension RSA {
  struct EncryptedPEM {
    let salt:Data
    let iv:Data
    let iterations:Int
    let ciphertext:Data
    let pemID:Data
    let pbkfd:Data
    let cipher:Data
  }
    
  /// Tests importing encrypted PEM private key with a plaintext password
  ///
  /// To decrypt an encrypted private RSA key...
  /// 1) Strip the headers of the PEM and base64 decode the data
  /// 2) Parse the data via ASN1 looking for the encryption algo, salt, iv and itterations used, and the ciphertext (aka octet string)
  /// 3) Derive the encryption key using PBKDF2 (sha1, salt and itterations)
  /// 4) Use encryption key to instantiate the AES CBC Cipher along with the IV
  /// 5) Decrypt the encrypted octet string
  /// 6) The decrypted octet string can be ASN1 parsed again for the private key octet string
  /// 7) This raw data can be used to instantiate a SecKey
  ///
  /// ```
  /// sequence(nodes: [
  ///   ASN1.Parser.Node.sequence(nodes: [
  ///       ASN1.Parser.Node.objectIdentifier(data: 9 bytes), //[42,134,72,134,247,13,1,5,13]
  ///       ASN1.Parser.Node.sequence(nodes: [
  ///           ASN1.Parser.Node.sequence(nodes: [
  ///               ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
  ///               ASN1.Parser.Node.sequence(nodes: [
  ///                   ASN1.Parser.Node.octetString(data: 8 bytes),       //SALT
  ///                   ASN1.Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
  ///               ])
  ///           ]),
  ///           ASN1.Parser.Node.sequence(nodes: [
  ///               ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc [96,134,72,1,101,3,4,1,2]
  ///               ASN1.Parser.Node.octetString(data: 16 bytes)           //IV
  ///           ])
  ///       ])
  ///   ]),
  ///   ASN1.Parser.Node.octetString(data: 640 bytes)
  /// ])
  /// ```
  private static func decodeEncryptedPEM(_ encryptedPEM:Data) throws -> EncryptedPEM {
    let asn = try ASN1.Parser.parse(data: encryptedPEM)
  
    var saltData:Data? = nil
    var ivData:Data? = nil
    var iterations:Int? = nil
    var ciphertextData:Data? = nil
  
    var pemID:Data? = nil
    var keyDerivationID:Data? = nil
    var cipherID:Data? = nil
  
    if case .sequence(let top) = asn {
      if case .sequence(let top1) = top.first {
        if case .objectIdentifier(let topID) = top1.first { pemID = topID }
        if case .sequence(let top2) = top1.last {
          if case .sequence(let top3) = top2.first {
            if case .objectIdentifier(let keyID) = top3.first { keyDerivationID = keyID }
            if case .sequence(let top4) = top3.last {
              if case .octetString(let salt) = top4.first {
                saltData = salt
              }
              if case .integer(let int) = top4.last {
                iterations = Int(int.toHexString(), radix: 16)
              }
            }
          }
          if case .sequence(let bottom3) = top2.last {
            if case .objectIdentifier(let cipher) = bottom3.first {
              cipherID = cipher
            }
            if case .octetString(let iv) = bottom3.last {
              ivData = iv
            }
          }
        }
      }
      if case .octetString(let cipherText) = top.last {
        ciphertextData = cipherText
      }
    }
  
    // Ensure we have everything we need to proceed...
    guard let saltData = saltData,
            let ivData = ivData,
            let iterations = iterations,
            let ciphertextData = ciphertextData,
            let pemID = pemID,
            let keyDerivationID = keyDerivationID,
            let cipherID = cipherID
    else {
        throw Error.invalidPEMFormat
    }
  
    return EncryptedPEM(salt: saltData, iv: ivData, iterations: iterations, ciphertext: ciphertextData, pemID: pemID, pbkfd: keyDerivationID, cipher: cipherID)
  }
}


//
//  PEM.swift
//  
//
//  Created by Brandon Toms on 5/26/22.
//

import Foundation


/// Conform to this protocol if your type can be instantiated from a ASN1 DER representation
protocol DERDecodable {
    /// The keys ASN1 object identifier (ex: RSA --> rsaEncryption --> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    static var objectIdentifier:Array<UInt8> { get }
    /// Instantiates an instance of your Public Key when given a DER representation of your Public Key
    init(publicDER: Array<UInt8>) throws
    /// Instantiates an instance of your Private Key when given a DER representation of your Private Key
    init(privateDER: Array<UInt8>) throws
    /// Instantiates a DERDecodable Key from a PEM string
    init<Key:DERDecodable>(pem: String, password: String?, asType:Key.Type) throws
    /// Instantiates a DERDecodable Key from ut8 decoded PEM data
    init<Key:DERDecodable>(pem: Data, password: String?, asType:Key.Type) throws
}

extension DERDecodable {
    
  /// Instantiates a DERDecodable Key from a PEM string
  /// - Parameters:
  ///   - pem: The PEM file to import
  ///   - password: A password to use to decrypt an encrypted PEM file
  ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
  init<Key:DERDecodable>(pem: String, password: String? = nil, asType:Key.Type = Key.self) throws {
      try self.init(pem: Data(pem.utf8), password: password, asType: Key.self)
  }
  
  /// Instantiates a DERDecodable Key from ut8 decoded PEM data
  /// - Parameters:
  ///   - pem: The PEM file to import
  ///   - password: A password to use to decrypt an encrypted PEM file
  ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
  init<Key:DERDecodable>(pem: Data, password: String? = nil, asType:Key.Type = Key.self) throws {
    let (type, bytes) = try PEM.pemToData(pem.bytes)
    
    if password != nil {
      guard type == .encryptedPrivateKey else { throw PEM.Error.invalidParameters }
    }
    
    switch type {
    case .publicRSAKeyDER:
      // Ensure the objectIdentifier is rsaEncryption
      try self.init(publicDER: bytes)
    case .privateRSAKeyDER:
      // Ensure the objectIdentifier is rsaEncryption
      try self.init(privateDER: bytes)
    case .publicKey:
      let der = try PEM.decodePublicKeyPEM(Data(bytes), expectedObjectIdentifier: Key.objectIdentifier)
      try self.init(publicDER: der)
    case .privateKey:
      let der = try PEM.decodePrivateKeyPEM(Data(bytes), expectedObjectIdentifier: Key.objectIdentifier)
      try self.init(privateDER: der)
    case .encryptedPrivateKey:
      // Decrypt the encrypted PEM and attempt to instantiate it again...
  
      // Ensure we were provided a password
      guard let password = password else { throw PEM.Error.invalidParameters }
  
      // Parse out Encryption Strategy and CipherText
      let decryptionStategy = try PEM.decodeEncryptedPEM(Data(bytes)) // RSA.decodeEncryptedPEM(Data(bytes))
  
      // Derive Encryption Key from Password
      let key = try decryptionStategy.pbkdfAlgorithm.deriveKey(password: password, ofLength: decryptionStategy.cipherAlgorithm.desiredKeyLength)
  
      // Decrypt CipherText
      let decryptedPEM = try decryptionStategy.cipherAlgorithm.decrypt(bytes: decryptionStategy.ciphertext, withKey: key)
  
      // Proceed with the unencrypted PEM (can public PEM keys be encrypted as well, wouldn't really make sense but idk if we should support it)?
      let der = try PEM.decodePrivateKeyPEM(Data(decryptedPEM), expectedObjectIdentifier: Key.objectIdentifier)
      try self.init(privateDER: der)
    }
  }
}

/// Conform to this protocol if your type can be described in an ASN1 DER representation
protocol DEREncodable {
  static var objectIdentifier:Array<UInt8> { get }
    
  func publicKeyDER() throws -> Array<UInt8>
  func privateKeyDER() throws -> Array<UInt8>
  
  /// PublicKey PEM Export Functions
    func exportPublicKeyPEM(withHeaderAndFooter:Bool) throws -> Array<UInt8>
  func exportPublicKeyPEMString(withHeaderAndFooter:Bool) throws -> String
  
  /// PrivateKey PEM Export Functions
  func exportPrivateKeyPEM(withHeaderAndFooter:Bool) throws -> Array<UInt8>
  func exportPrivateKeyPEMString(withHeaderAndFooter:Bool) throws -> String
}

extension DEREncodable {
  func exportPublicKeyPEM(withHeaderAndFooter:Bool = true) throws -> Array<UInt8> {
    let publicDER = try self.publicKeyDER()
    let asnNodes:ASN1.Parser.Node = .sequence(nodes: [
      .sequence(nodes: [
        .objectIdentifier(data: Data(Self.objectIdentifier)),
        .null
      ]),
      .bitString(data: Data( publicDER ))
    ])
  
    let base64String = ASN1.Encoder.encode(asnNodes).toBase64()
    let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
    let bodyUTF8Bytes = bodyString.bytes
    
    if withHeaderAndFooter {
      let header = PEM.PEMType.publicKey.headerBytes + [0x0a]
      let footer = [0x0a] + PEM.PEMType.publicKey.footerBytes
    
      return header + bodyUTF8Bytes + footer
    } else {
      return bodyUTF8Bytes
    }
  }
  
  func exportPublicKeyPEMString(withHeaderAndFooter:Bool = true) throws -> String {
    let publicPEMData = try exportPublicKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
    guard let pemAsString = String(data: Data(publicPEMData), encoding: .utf8) else {
    throw PEM.Error.encodingError
    }
    return pemAsString
  }
  
  func exportPrivateKeyPEM(withHeaderAndFooter:Bool = true) throws -> Array<UInt8> {
    let privateDER = try self.privateKeyDER()
    let asnNodes:ASN1.Parser.Node = .sequence(nodes: [
      .integer(data: Data(hex: "0x00")),
      .sequence(nodes: [
        .objectIdentifier(data: Data(Self.objectIdentifier)),
        .null
      ]),
      .octetString(data: Data( privateDER ))
    ])
      
    let base64String = ASN1.Encoder.encode(asnNodes).toBase64()
    let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
    let bodyUTF8Bytes = bodyString.bytes
    
    if withHeaderAndFooter {
      let header = PEM.PEMType.privateKey.headerBytes + [0x0a]
      let footer = [0x0a] + PEM.PEMType.privateKey.footerBytes
    
      return header + bodyUTF8Bytes + footer
    } else {
      return bodyUTF8Bytes
    }
  }
  
  func exportPrivateKeyPEMString(withHeaderAndFooter:Bool = true) throws -> String {
    let privatePEMData = try exportPrivateKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
    guard let pemAsString = String(data: Data(privatePEMData), encoding: .utf8) else {
      throw PEM.Error.encodingError
    }
    return pemAsString
  }
}

/// Conform to this protocol if your type can both be instantiated and expressed by an ASN1 DER representation.
protocol DERCodable: DERDecodable, DEREncodable { }

struct DER {
  /// Integer to Octet String Primitive
  /// - Parameters:
  ///   - x: nonnegative integer to be converted
  ///   - size: intended length of the resulting octet string
  /// - Returns: corresponding octet string of length xLen
  /// - Note: https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
  internal static func i2osp(x:[UInt8], size:Int) -> [UInt8] {
    var modulus = x
    while modulus.count < size {
      modulus.insert(0x00, at: 0)
    }
    if modulus[0] >= 0x80 {
        modulus.insert(0x00, at: 0)
    }
    return modulus
  }
    
  /// Integer to Octet String Primitive
  /// - Parameters:
  ///   - x: nonnegative integer to be converted
  ///   - size: intended length of the resulting octet string
  /// - Returns: corresponding octet string of length xLen
  /// - Note: https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
  internal static func i2ospData(x:[UInt8], size:Int) -> Data {
    return Data(DER.i2osp(x: x, size: size))
  }
}

struct PEM {
    
  public enum Error: Swift.Error {
    /// An error occured while encoding the PEM file
    case encodingError
    /// An error occured while decoding the PEM file
    case decodingError
    /// Encountered an unsupported PEM type
    case unsupportedPEMType
    /// Encountered an invalid/unexpected PEM format
    case invalidPEMFormat
    /// Encountered an invalid/unexpected PEM header string/delimiter
    case invalidPEMHeader
    /// Encountered an invalid/unexpected PEM footer string/delimiter
    case invalidPEMFooter
    /// Encountered a invalid/unexpected parameters while attempting to decode a PEM file
    case invalidParameters
    /// Encountered an unsupported Cipher algorithm while attempting to decrypt an encrypted PEM file
    case unsupportedCipherAlgorithm([UInt8])
    /// Encountered an unsupported Password Derivation algorithm while attempting to decrypt an encrypted PEM file
    case unsupportedPBKDFAlgorithm([UInt8])
    /// The instiating types objectIdentifier does not match that of the PEM file
    case objectIdentifierMismatch(got:[UInt8], expected:[UInt8])
  }
    
  // MARK: Add support for additional PEM types here
    
  /// General PEM Classification
  internal enum PEMType {
    // Direct DER Exports for RSA Keys (special case)
    case publicRSAKeyDER
    case privateRSAKeyDER
  
    // Generale PEM Headers
    case publicKey
    case privateKey
    case encryptedPrivateKey
  
    // Others
    //case certificate
  
    init(headerBytes: ArraySlice<UInt8>) throws {
      guard headerBytes.count > 10 else { throw PEM.Error.unsupportedPEMType }
      let bytes = headerBytes.dropFirst(5).dropLast(5)
      switch bytes {
      //"BEGIN RSA PUBLIC KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59]:
        self = .publicRSAKeyDER

      //"BEGIN RSA PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .privateRSAKeyDER

      //"BEGIN PUBLIC KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59]:
        self = .publicKey

      //"BEGIN PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .privateKey

      //"BEGIN ENCRYPTED PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .encryptedPrivateKey

      default:
        throw PEM.Error.unsupportedPEMType
      }
    }
  
    /// This PEM type's header string (expressed as the utf8 decoded byte representation)
    var headerBytes:Array<UInt8> {
      switch self {
      case .publicRSAKeyDER:
          return "-----BEGIN RSA PUBLIC KEY-----".bytes
      case .privateRSAKeyDER:
          return "-----BEGIN RSA PRIVATE KEY-----".bytes
      case .publicKey:
          return "-----BEGIN PUBLIC KEY-----".bytes
      case .privateKey:
          return "-----BEGIN PRIVATE KEY-----".bytes
      case .encryptedPrivateKey:
          return "-----BEGIN ENCRYPTED PRIVATE KEY-----".bytes
      }
    }

    /// This PEM type's footer string (expressed as the utf8 decoded byte representation)
    var footerBytes:Array<UInt8> {
      switch self {
      case .publicRSAKeyDER:
          return "-----END RSA PUBLIC KEY-----".bytes
      case .privateRSAKeyDER:
          return "-----END RSA PRIVATE KEY-----".bytes
      case .publicKey:
          return "-----END PUBLIC KEY-----".bytes
      case .privateKey:
          return "-----END PRIVATE KEY-----".bytes
      case .encryptedPrivateKey:
          return "-----END ENCRYPTED PRIVATE KEY-----".bytes
      }
    }
  }
    
  /// Converts UTF8 Encoding of PEM file into a PEMType and the base64 decoded key data
  /// - Parameter data: The `UTF8` encoding of the PEM file
  /// - Returns: A tuple containing the PEMType, and the actual base64 decoded PEM data (with the headers and footers removed).
  internal static func pemToData(_ data:Array<UInt8>) throws -> (type: PEMType, bytes: Array<UInt8>) {
    let fiveDashes = ArraySlice<UInt8>(repeating: 0x2D, count: 5) // "-----".bytes.toHexString()
    let chunks = data.split(separator: 0x0a) // 0x0a == "\n" `new line` char
    guard chunks.count > 2 else { throw PEM.Error.invalidPEMFormat }
  
    // Enforce a valid PEM header
    guard let header = chunks.first,
      header.count > 10,
      header.prefix(5) == fiveDashes,
      header.suffix(5) == fiveDashes else {
        throw PEM.Error.invalidPEMHeader
    }
  
    // Enforce a valid PEM footer
    guard let footer = chunks.last,
      footer.count > 10,
      footer.prefix(5) == fiveDashes,
      footer.suffix(5) == fiveDashes else {
        throw PEM.Error.invalidPEMFooter
    }
  
    // Attempt to classify the PEMType based on the header
    //
    // - Note: This just gives us a general idea of what direction to head in. Headers that don't match the underlying data will end up throwing an Error later
    let pemType:PEMType = try PEMType(headerBytes: header)
  
    guard let base64 = String(data: Data(chunks[1..<chunks.count-1].joined()), encoding: .utf8) else { throw Error.invalidPEMFormat }
    guard let pemData = Data(base64Encoded: base64) else { throw Error.invalidPEMFormat }
  
    // return the PEMType and PEM Data (without header & footer)
    return (type: pemType, bytes: pemData.bytes)
  }
    
  /// Decodes an ASN1 formatted Public Key into it's raw DER representation
  /// - Parameters:
  ///   - pem: The ASN1 encoded Public Key representation
  ///   - expectedObjectIdentifier: The expected objectIdentifier for the particular key type
  /// - Returns: The raw bitString data (Public Key DER)
  ///
  /// ```
  /// 0:d=0  hl=4 l= 546 cons: SEQUENCE
  /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
  /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
  /// 17:d=2  hl=2 l=   0 prim:   NULL
  /// 19:d=1  hl=4 l= 527 prim:  BIT STRING
  /// ```
  internal static func decodePublicKeyPEM(_ pem:Data, expectedObjectIdentifier:Array<UInt8>) throws -> Array<UInt8> {
    let asn = try ASN1.Parser.parse(data: pem)
    
    // Enforce the above ASN1 Structure
    guard case .sequence(let sequence) = asn else { throw Error.invalidPEMFormat }
    guard sequence.count == 2 else { throw Error.invalidPEMFormat }
    guard case .sequence(let params) = sequence.first else { throw Error.invalidPEMFormat }
    guard params.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objectID) = params.first else { throw Error.invalidPEMFormat }
    guard case .null = params.last else { throw Error.invalidPEMFormat }
    guard case .bitString(let bits) = sequence.last else { throw Error.invalidPEMFormat }
  
    // Ensure the ObjectID specified in the PEM matches that of the Key.Type we're attempting to instantiate
    guard objectID.bytes == expectedObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectID.bytes, expected: expectedObjectIdentifier) }
  
    return bits.bytes
  }
    
  /// Decodes an ASN1 formatted Private Key into it's raw DER representation
  /// - Parameters:
  ///   - pem: The ASN1 encoded Private Key representation
  ///   - expectedObjectIdentifier: The expected objectIdentifier for the particular key type
  /// - Returns: The raw octetString data (Private Key DER)
  ///
  /// ```
  /// 0:d=0  hl=4 l= 630 cons: SEQUENCE
  /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
  /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
  /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
  /// 20:d=2  hl=2 l=   0 prim:   NULL
  /// 22:d=1  hl=4 l= 608 prim:  OCTET STRING      [HEX DUMP]:3082...AA50
  /// ```
  internal static func decodePrivateKeyPEM(_ pem:Data, expectedObjectIdentifier:Array<UInt8>) throws -> Array<UInt8> {
    let asn = try ASN1.Parser.parse(data: pem)
  
    // Enforce the above ASN1 Structure
    guard case .sequence(let sequence) = asn else { throw Error.invalidPEMFormat }
    guard sequence.count == 3 else { throw Error.invalidPEMFormat }
    guard case .integer(let integer) = sequence[0] else { throw Error.invalidPEMFormat }
    guard case .sequence(let params) = sequence[1] else { throw Error.invalidPEMFormat }
    guard params.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objectID) = params.first else { throw Error.invalidPEMFormat }
    guard case .null = params.last else { throw Error.invalidPEMFormat }
    guard case .octetString(let octet) = sequence[2] else { throw Error.invalidPEMFormat }
  
    // Ensure the ObjectID specified in the PEM matches that of the Key.Type we're attempting to instantiate
    guard objectID.bytes == expectedObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectID.bytes, expected: expectedObjectIdentifier) }
    guard integer == Data(hex: "0x00") else { throw Error.invalidPEMFormat }
  
    return octet.bytes
  }
}


// MARK: Encrypted PEM

extension PEM {
    
  fileprivate struct EncryptedPEM {
    let objectIdentifer:[UInt8]
    let ciphertext:[UInt8]
    let pbkdfAlgorithm:PBKDFAlgorithm
    let cipherAlgorithm:CipherAlgorithm
  }

  /// Attempts to decode an encrypted Private Key PEM, returning all of the information necessary to decrypt the encrypted PEM
  /// - Parameter encryptedPEM: The raw base64 decoded PEM data
  /// - Returns: An `EncryptedPEM` Struct containing the ciphertext, the pbkdf alogrithm for key derivation, the cipher algorithm for decrypting and the objectIdentifier describing the contents of this PEM data
  ///
  /// To decrypt an encrypted PEM Private Key...
  /// 1) Strip the headers of the PEM and base64 decode the data
  /// 2) Parse the data via ASN1 looking for both the pbkdf and cipher algorithms, their respective parameters (salt, iv and itterations) and the ciphertext (aka octet string))
  /// 3) Derive the encryption key using the appropriate pbkdf alogorithm, found in step 2
  /// 4) Use the encryption key to instantiate the appropriate cipher algorithm, also found in step 2
  /// 5) Decrypt the encrypted ciphertext (the contents of the octetString node)
  /// 6) The decrypted octet string can now be handled like any other Private Key PEM
  ///
  /// ```
  /// sequence(nodes: [
  ///   ASN1.Parser.Node.sequence(nodes: [
  ///       ASN1.Parser.Node.objectIdentifier(data: 9 bytes),              // PEM's ObjectIdentifier
  ///       ASN1.Parser.Node.sequence(nodes: [
  ///           ASN1.Parser.Node.sequence(nodes: [
  ///               ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      // PBKDF Algorithm
  ///               ASN1.Parser.Node.sequence(nodes: [
  ///                   ASN1.Parser.Node.octetString(data: 8 bytes),       // SALT
  ///                   ASN1.Parser.Node.integer(data: 2 bytes)            // ITERATIONS
  ///               ])
  ///           ]),
  ///           ASN1.Parser.Node.sequence(nodes: [
  ///               ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      // Cipher Algorithm (ex: des-ede3-cbc)
  ///               ASN1.Parser.Node.octetString(data: 16 bytes)           // Initial Vector (IV)
  ///           ])
  ///       ])
  ///   ]),
  ///   ASN1.Parser.Node.octetString(data: 640 bytes)
  /// ])
  /// ```
  fileprivate static func decodeEncryptedPEM(_ encryptedPEM:Data) throws -> EncryptedPEM {
    let asn = try ASN1.Parser.parse(data: encryptedPEM)
    
    guard case .sequence(let encryptedPEMWrapper) = asn else { throw Error.invalidPEMFormat }
    guard encryptedPEMWrapper.count == 2 else { throw Error.invalidPEMFormat }
    guard case .sequence(let encryptionInfoWrapper) = encryptedPEMWrapper.first else { throw Error.invalidPEMFormat }
    guard encryptionInfoWrapper.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objID) = encryptionInfoWrapper.first else { throw Error.invalidPEMFormat }
    guard case .sequence(let encryptionAlgorithmsWrapper) = encryptionInfoWrapper.last else { throw Error.invalidPEMFormat }
    guard encryptionAlgorithmsWrapper.count == 2 else { throw Error.invalidPEMFormat }
    let pbkdf = try decodePBKFD(encryptionAlgorithmsWrapper.first!)
    let cipher = try decodeCipher(encryptionAlgorithmsWrapper.last!)
    guard case .octetString(let octets) = encryptedPEMWrapper.last else { throw Error.invalidPEMFormat }
  
    return EncryptedPEM(objectIdentifer: objID.bytes, ciphertext: octets.bytes, pbkdfAlgorithm: pbkdf, cipherAlgorithm: cipher)
  }
}


// MARK: Encrypted PEM PBKDF Algorithms

extension PEM {
  // MARK: Add support for new PBKDF Algorithms here...
  fileprivate enum PBKDFAlgorithm {
    case pbkdf2(salt: [UInt8], iterations: Int)
  
    init(objID:[UInt8], salt:[UInt8], iterations:[UInt8]) throws {
      guard let iterations = Int(iterations.toHexString(), radix: 16) else { throw Error.invalidPEMFormat }
      switch objID {
      case [42, 134, 72, 134, 247, 13, 1, 5, 12]: // pbkdf2
        self = .pbkdf2(salt: salt, iterations: iterations)
      default:
        throw Error.unsupportedPBKDFAlgorithm(objID)
      }
    }
  
    func deriveKey(password:String, ofLength keyLength:Int, usingHashVarient variant:HMAC.Variant = .sha1) throws -> [UInt8] {
      switch self {
      case .pbkdf2(let salt, let iterations):
        return try PKCS5.PBKDF2(password: password.bytes, salt: salt, iterations: iterations, keyLength: keyLength, variant: variant).calculate()
      //default:
      //    throw Error.invalidPEMFormat
      }
    }
  }
  
  /// Decodes the PBKDF ASN1 Block in an Encrypted Private Key PEM file
  /// - Parameter node: The ASN1 sequence node containing the pbkdf parameters
  /// - Returns: The PBKDFAlogrithm if supported
  ///
  /// Expects an ASN1.Node with the following structure
  /// ```
  /// ASN1.Parser.Node.sequence(nodes: [
  ///     ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
  ///     ASN1.Parser.Node.sequence(nodes: [
  ///         ASN1.Parser.Node.octetString(data: 8 bytes),       //SALT
  ///         ASN1.Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
  ///     ])
  /// ])
  /// ```
  fileprivate static func decodePBKFD(_ node:ASN1.Parser.Node) throws -> PBKDFAlgorithm {
    guard case .sequence(let wrapper) = node else { throw Error.invalidPEMFormat }
    guard wrapper.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objID) = wrapper.first else { throw Error.invalidPEMFormat }
    guard case .sequence(let params) = wrapper.last else { throw Error.invalidPEMFormat }
    guard params.count == 2 else { throw Error.invalidPEMFormat }
    guard case .octetString(let salt) = params.first else { throw Error.invalidPEMFormat }
    guard case .integer(let iterations) = params.last else { throw Error.invalidPEMFormat }
  
    return try PBKDFAlgorithm(objID: objID.bytes, salt: salt.bytes, iterations: iterations.bytes)
  }
}


// MARK: Encrypted PEM Cipher Algorithms

extension PEM {
  // MARK: Add support for new Cipher Algorithms here...
  fileprivate enum CipherAlgorithm {
    case aes_128_cbc(iv:[UInt8])
    case aes_256_cbc(iv:[UInt8])
  
    init(objID:[UInt8], iv:[UInt8]) throws {
      switch objID {
      case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]: // aes-128-cbc
        self = .aes_128_cbc(iv: iv)
      case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]: // aes-256-cbc
        self = .aes_256_cbc(iv: iv)
      default:
        throw Error.unsupportedCipherAlgorithm(objID)
      }
    }
  
    func decrypt(bytes: [UInt8], withKey key:[UInt8]) throws -> [UInt8] {
      switch self {
      case .aes_128_cbc(let iv):
        return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).decrypt(bytes)
      case .aes_256_cbc(let iv):
        return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).decrypt(bytes)
      //default:
        //throw Error.invalidPEMFormat
      }
    }
  
    /// The key length used for this Cipher strategy
    /// - Note: we need this information when deriving the key using our PBKDF strategy
    var desiredKeyLength:Int {
      switch self {
      case .aes_128_cbc: return 16
      case .aes_256_cbc: return 32
      }
    }
  }
  
  /// Decodes the Cipher ASN1 Block in an Encrypted Private Key PEM file
  /// - Parameter node: The ASN1 sequence node containing the cipher parameters
  /// - Returns: The CipherAlogrithm if supported
  ///
  /// Expects an ASN1.Node with the following structure
  /// ```
  /// ASN1.Parser.Node.sequence(nodes: [
  ///     ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc
  ///     ASN1.Parser.Node.octetString(data: 16 bytes)           //IV
  /// ])
  /// ```
  fileprivate static func decodeCipher(_ node:ASN1.Parser.Node) throws -> CipherAlgorithm {
    guard case .sequence(let params) = node else { throw Error.invalidPEMFormat }
    guard params.count == 2 else { throw Error.invalidPEMFormat }
    guard case .objectIdentifier(let objID) = params.first else { throw Error.invalidPEMFormat }
    guard case .octetString(let initialVector) = params.last else { throw Error.invalidPEMFormat }
  
    return try CipherAlgorithm(objID: objID.bytes, iv: initialVector.bytes)
  }
}

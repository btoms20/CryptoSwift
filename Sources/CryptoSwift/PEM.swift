//
//  PEM.swift
//  
//
//  Created by Brandon Toms on 5/26/22.
//

import Foundation


protocol DERDecodable {
    static var objectIdentifier:Array<UInt8> { get }
    //init(der:Array<UInt8>) throws
    //init(publicDer: ASN1.Parser.Node) throws
    //init(privateDer: ASN1.Parser.Node) throws
    init(publicDER: Array<UInt8>) throws
    init(privateDER: Array<UInt8>) throws
    init<Key:DERDecodable>(pem: String, password: String?, asType:Key.Type) throws
    init<Key:DERDecodable>(pem: Data, password: String?, asType:Key.Type) throws
}

extension DERDecodable {
  init<Key:DERDecodable>(pem: String, password: String? = nil, asType:Key.Type = Key.self) throws {
      try self.init(pem: Data(pem.utf8), password: password, asType: Key.self)
  }
  
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
      let der = try PEM.decodePublicPEM(Data(bytes), expectedObjectIdentifier: Key.objectIdentifier)
      try self.init(publicDER: der)
    case .privateKey:
      let der = try PEM.decodePrivatePEM(Data(bytes), expectedObjectIdentifier: Key.objectIdentifier)
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
  
      // Init from Raw Representation
      //print(decryptedPEM)
  
      // Proceed with the unencrypted PEM (can public PEM keys be encrypted as well, wouldn't really make sense but idk if we should support it)?
      let der = try PEM.decodePrivatePEM(Data(decryptedPEM), expectedObjectIdentifier: Key.objectIdentifier)
      try self.init(privateDER: der)
    }
  }
}

protocol DEREncodable {
  func publicKeyDER() throws -> Array<UInt8>
  func privateKeyDER() throws -> Array<UInt8>
  
  /// PublicKey PEM Export Functions
  func exportPublicKeyPEM() throws -> Array<UInt8>
  func exportPublicKeyPEMString() throws -> String
  
  /// PrivateKey PEM Export Functions
  func exportPrivateKeyPEM() throws -> Array<UInt8>
  func exportPrivateKeyPEMString() throws -> String
}

extension DEREncodable {
  func exportPublicKeyPEM() throws -> Array<UInt8> {
    throw PEM.Error.invalidPEMFormat
  }
  func exportPublicKeyPEMString() throws -> String {
    throw PEM.Error.invalidPEMFormat
  }
  
  func exportPrivateKeyPEM() throws -> Array<UInt8> {
    throw PEM.Error.invalidPEMFormat
  }
  func exportPrivateKeyPEMString() throws -> String {
    throw PEM.Error.invalidPEMFormat
  }
}

protocol DERCodable: DERDecodable, DEREncodable { }

struct PEM {
    
  public enum Error: Swift.Error {
    case unsupportedPEMType
    case invalidDERFormat
    case invalidPEMFormat
    case invalidPEMHeader
    case invalidPEMFooter
    case invalidParameters
    case unsupportedKeyType
    case unsupportedCipherAlgorithm([UInt8])
    case unsupportedPBKDFAlgorithm([UInt8])
    case objectIdentifierMismatch(got:[UInt8], expected:[UInt8])
  }
  
  /// An enum containing all of the support PEM Key types
  enum KeyType {
    case rsaEncryption
    case encryptedPem
  
    init(objectIdentifier:Array<UInt8>) throws {
      switch objectIdentifier {
      case Array<UInt8>(arrayLiteral: 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x01, 0x01, 0x01):
        self = .rsaEncryption
      case Array<UInt8>(arrayLiteral: 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x01, 0x05, 0x0D):
        self = .encryptedPem
      default:
        throw Error.unsupportedKeyType
      }
    }
  }
    
  internal enum PEMType {
    // Direct DER Exports for RSA Keys (special case)
    case publicRSAKeyDER
    case privateRSAKeyDER
  
    // Generale PEM Headers
    case publicKey
    case privateKey
    case encryptedPrivateKey
  
    // others
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
  
    var headerBytes:String {
      switch self {
      case .publicRSAKeyDER:
        return "-----BEGIN RSA PUBLIC KEY-----"
      case .privateRSAKeyDER:
        return "-----BEGIN RSA PRIVATE KEY-----"
      case .publicKey:
        return "-----BEGIN PUBLIC KEY-----"
      case .privateKey:
        return "-----BEGIN PRIVATE KEY-----"
      case .encryptedPrivateKey:
        return "-----BEGIN ENCRYPTED PRIVATE KEY-----"
      }
    }

    var footerBytes:String {
      switch self {
      case .publicRSAKeyDER:
        return "-----END RSA PUBLIC KEY-----"
      case .privateRSAKeyDER:
        return "-----END RSA PRIVATE KEY-----"
      case .publicKey:
        return "-----END PUBLIC KEY-----"
      case .privateKey:
        return "-----END PRIVATE KEY-----"
      case .encryptedPrivateKey:
        return "-----END ENCRYPTED PRIVATE KEY-----"
      }
    }
  }
    
  /// Converts UTF8 Encoding of PEM file into a PEMType and the base64 decoded key data
  /// - Parameter data: The `UTF8` encoding of the PEM file
  /// - Returns: A tuple containing the PEMType, and the actual base64 decoded PEM data (with the headers and footers removed).
  internal static func pemToData(_ data:Array<UInt8>) throws -> (type: PEMType, bytes: Array<UInt8>) {
    let fiveDashes = ArraySlice<UInt8>(arrayLiteral: 0x2D, 0x2D, 0x2D, 0x2D, 0x2D) // "-----".bytes.toHexString()
    let chunks = data.split(separator: 0x0a)
    guard chunks.count > 2 else { throw PEM.Error.invalidPEMFormat }
  
    /// Enforce a valid PEM header
    guard let header = chunks.first,
      header.count > 10,
      header.prefix(5) == fiveDashes,
      header.suffix(5) == fiveDashes else {
        print("Header: \(Array<UInt8>(chunks.first ?? []).toHexString())")
        throw PEM.Error.invalidPEMHeader
    }
  
    /// Enforce a valid PEM footer
    guard let footer = chunks.last,
      footer.count > 10,
      footer.prefix(5) == fiveDashes,
      footer.suffix(5) == fiveDashes else {
        print("Footer: \(Array<UInt8>(chunks.last ?? []).toHexString()))")
        throw PEM.Error.invalidPEMFooter
    }
  
    /// Attempt to classify the PEMType based on the header
    ///
    /// - Note: This just gives us a general idea of what direction to head in. Headers that don't match the underlying data will throw an Error
    let pemType:PEMType = try PEMType(headerBytes: header)
  
    /// join the data (is this correct? dont we have to convert from base64Encoded at some point?)
    guard let base64 = String(data: Data(chunks[1..<chunks.count-1].joined()), encoding: .utf8) else { throw Error.invalidPEMFormat }
    guard let pemData = Data(base64Encoded: base64) else { throw Error.invalidPEMFormat }
    //let pemData = Data(chunks[1..<chunks.count-1].joined())
  
    /// return the PEMType and PEM Data (without header & footer)
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
  internal static func decodePublicPEM(_ pem:Data, expectedObjectIdentifier:Array<UInt8>) throws -> Array<UInt8> {
    let asn = try ASN1.Parser.parse(data: pem)
  
    print("Public PEM")
    print(asn)
  
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
  internal static func decodePrivatePEM(_ pem:Data, expectedObjectIdentifier:Array<UInt8>) throws -> Array<UInt8> {
    let asn = try ASN1.Parser.parse(data: pem)
  
    print("Private PEM")
    print(asn)
  
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
  
    print(asn)
  
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
  
  fileprivate enum CipherAlgorithm {
    case aes_128_cbc(iv:[UInt8])
    case aes_256_cbc(iv:[UInt8])
    //case des_ede3_cbc(iv:[UInt8])
  
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

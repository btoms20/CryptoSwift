//
//  CryptoSwift
//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
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

// MARK: PEMCodable Protocol

protocol PEMCodable:PEMEncodable, PEMDecodable { }

struct PEM {
  enum Error:Swift.Error {
    case notYetImplemented
  }
  /// The PKCS8 ObjectIdentifier used to identify the contents of PEM files.
  enum ObjectIdentifier {
    static var rsaEncryption:[UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    
    case objectIdentifier(Array<UInt8>)
    case null
    case notPresent
  }
}


// MARK: PEMEncodable Protocol

protocol PEMEncodable:DEREncodable {
  /// The keys ASN1 primary object identifier (ex: RSA --> rsaEncryption --> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
  static var primaryObjectIdentifier:PEM.ObjectIdentifier { get }
  /// The keys ASN1 secondary object identifier (ex: RSA --> .null)
  static var secondaryObjectIdentifier:PEM.ObjectIdentifier { get }
}

extension PEMEncodable {
  /// PublicKey PEM Export Functions
  func exportPublicKeyPEM(withHeaderAndFooter:Bool) throws -> Array<UInt8> {
    throw PEM.Error.notYetImplemented
  }
  func exportPublicKeyPEMString(withHeaderAndFooter:Bool) throws -> String {
    throw PEM.Error.notYetImplemented
  }
  
  /// PrivateKey PEM Export Functions
  func exportPrivateKeyPEM(withHeaderAndFooter:Bool) throws -> Array<UInt8> {
    throw PEM.Error.notYetImplemented
  }
  func exportPrivateKeyPEMString(withHeaderAndFooter:Bool) throws -> String {
    throw PEM.Error.notYetImplemented
  }
}


// MARK: PEMDecodable Protocol

protocol PEMDecodable:DERDecodable {
  /// The keys ASN1 primary object identifier (ex: RSA --> rsaEncryption --> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
  static var primaryObjectIdentifier:PEM.ObjectIdentifier { get }
  /// The keys ASN1 secondary object identifier (ex: RSA --> .null)
  static var secondaryObjectIdentifier:PEM.ObjectIdentifier { get }
}

extension PEMDecodable {
  /// Instantiates a DERDecodable Key from a PEM string
  /// - Parameters:
  ///   - pem: The PEM file to import
  ///   - password: A password to use to decrypt an encrypted PEM file
  ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
  init<Key:PEMDecodable>(pem: String, password: String? = nil, asType:Key.Type = Key.self) throws {
    throw PEM.Error.notYetImplemented
  }
}



//
//  CryptoSwift
//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  In no event will the authors be held liable for any damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
//
//  - The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
//  - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
//  - This notice may not be removed or altered from any source or binary distribution.
//
//  Original Asn1Parser.swift by SwiftyRSA
//
//  Created by Lois Di Qual on 5/9/17.
//  Copyright © 2017 Scoop. All rights reserved.
//
//  Modified by Brandon Toms on 5/1/22
//

import Foundation

/// Simple data scanner that consumes bytes from a raw data and keeps an updated position.
private class Scanner {
  
  enum ScannerError: Error {
    case outOfBounds
  }
  
  let data: Data
  var index: Int = 0
  
  /// Returns whether there is no more data to consume
  var isComplete: Bool {
    return index >= data.count
  }
  
  /// Creates a scanner with provided data
  ///
  /// - Parameter data: Data to consume
  init(data: Data) {
    self.data = data
  }
  
  /// Consumes data of provided length and returns it
  ///
  /// - Parameter length: length of the data to consume
  /// - Returns: data consumed
  /// - Throws: ScannerError.outOfBounds error if asked to consume too many bytes
  func consume(length: Int) throws -> Data {
      
    guard length > 0 else {
      return Data()
    }
    
    guard index + length <= data.count else {
      throw ScannerError.outOfBounds
    }
    
    let subdata = data.subdata(in: index..<index + length)
    index += length
    return subdata
  }
  
  /// Consumes a primitive, definite ASN1 length and returns its value.
  ///
  /// See http://luca.ntop.org/Teaching/Appunti/asn1.html,
  ///
  /// - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
  /// - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and
  ///   bits 7-1 give the number of additional length octets.
  ///   Second and following octets give the length, base 256, most significant digit first.
  ///
  /// - Returns: Length that was consumed
  /// - Throws: ScannerError.outOfBounds error if asked to consume too many bytes
  func consumeLength() throws -> Int {
      
    let lengthByte = try consume(length: 1).firstByte
    
    // If the first byte's value is less than 0x80, it directly contains the length
    // so we can return it
    guard lengthByte >= 0x80 else {
      return Int(lengthByte)
    }
    
    // If the first byte's value is more than 0x80, it indicates how many following bytes
    // will describe the length. For instance, 0x85 indicates that 0x85 - 0x80 = 0x05 = 5
    // bytes will describe the length, so we need to read the 5 next bytes and get their integer
    // value to determine the length.
    let nextByteCount = lengthByte - 0x80
    let length = try consume(length: Int(nextByteCount))
    
    return length.integer
  }
}

private extension Data {
    
  /// Returns the first byte of the current data
  var firstByte: UInt8 {
    var byte: UInt8 = 0
    copyBytes(to: &byte, count: MemoryLayout<UInt8>.size)
    return byte
  }
  
  /// Returns the integer value of the current data.
  /// @warning: this only supports data up to 4 bytes, as we can only extract 32-bit integers.
  var integer: Int {
      
    guard count > 0 else {
      return 0
    }
    
    var int: UInt32 = 0
    var offset: Int32 = Int32(count - 1)
    forEach { byte in
      let byte32 = UInt32(byte)
      let shifted = byte32 << (UInt32(offset) * 8)
      int = int | shifted
      offset -= 1
    }
    
    return Int(int)
  }
}

enum ASN1 {
  private enum IDENTIFIERS:UInt8, Equatable {
    case SEQUENCE    = 0x30
    case INTERGER    = 0x02
    case OBJECTID    = 0x06
    case NULL        = 0x05
    case BITSTRING   = 0x03
    case OCTETSTRING = 0x04
    
    static func == (lhs:UInt8, rhs:IDENTIFIERS) -> Bool {
      lhs == rhs.rawValue
    }
    
    var bytes:[UInt8] {
      switch self {
      case .NULL:
        return [self.rawValue, 0x00]
      default:
        return [self.rawValue]
      }
    }
  }
    
  /// A simple ASN1 parser that will recursively iterate over a root node and return a Node tree.
  /// The root node can be any of the supported nodes described in `Node`. If the parser encounters a sequence
  /// it will recursively parse its children.
  enum Parser {
      
    /// An ASN1 node
    enum Node:CustomStringConvertible {
      case sequence(nodes: [Node])
      case integer(data: Data)
      case objectIdentifier(data: Data)
      case null
      case bitString(data: Data)
      case octetString(data: Data)
      
      var description: String {
        printNode(self, level: 0)
      }
    }
    
    enum ParserError: Error {
      case noType
      case invalidType(value: UInt8)
    }
    
    /// Parses ASN1 data and returns its root node.
    ///
    /// - Parameter data: ASN1 data to parse
    /// - Returns: Root ASN1 Node
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    static func parse(data: Data) throws -> Node {
      let scanner = Scanner(data: data)
      let node = try parseNode(scanner: scanner)
      return node
    }
    
    /// Parses an ASN1 given an existing scanne.
    /// @warning: this will modify the state (ie: position) of the provided scanner.
    ///
    /// - Parameter scanner: Scanner to use to consume the data
    /// - Returns: Parsed node
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    private static func parseNode(scanner: Scanner) throws -> Node {
      
      let firstByte = try scanner.consume(length: 1).firstByte
              
      // Sequence
      if firstByte == IDENTIFIERS.SEQUENCE {
        let length = try scanner.consumeLength()
        let data = try scanner.consume(length: length)
        let nodes = try parseSequence(data: data)
        return .sequence(nodes: nodes)
      }
      
      // Integer
      if firstByte == IDENTIFIERS.INTERGER {
        let length = try scanner.consumeLength()
        let data = try scanner.consume(length: length)
        return .integer(data: data)
      }
      
      // Object identifier
      if firstByte == IDENTIFIERS.OBJECTID {
        let length = try scanner.consumeLength()
        let data = try scanner.consume(length: length)
        return .objectIdentifier(data: data)
      }
      
      // Null
      if firstByte == IDENTIFIERS.NULL {
        _ = try scanner.consume(length: 1)
        return .null
      }
      
      // Bit String
      if firstByte == IDENTIFIERS.BITSTRING {
        let length = try scanner.consumeLength()
        
        // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
        // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
        _ = try scanner.consume(length: 1)
        
        let data = try scanner.consume(length: length - 1)
        return .bitString(data: data)
      }
      
      // Octet String
      if firstByte == IDENTIFIERS.OCTETSTRING {
        let length = try scanner.consumeLength()
        let data = try scanner.consume(length: length)
        return .octetString(data: data)
      }
      
      throw ParserError.invalidType(value: firstByte)
    }
        
    /// Parses an ASN1 sequence and returns its child nodes
    ///
    /// - Parameter data: ASN1 data
    /// - Returns: A list of ASN1 nodes
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    private static func parseSequence(data: Data) throws -> [Node] {
      let scanner = Scanner(data: data)
      var nodes: [Node] = []
      while !scanner.isComplete {
        let node = try parseNode(scanner: scanner)
        nodes.append(node)
      }
      return nodes
    }
  }
    
  enum Encoder {
    /// Encodes an ASN1Node into it's byte representation
    ///
    /// - Parameter node: The Node to encode
    /// - Returns: The encoded bytes as a UInt8 array
    public static func encode(_ node:ASN1.Parser.Node) -> [UInt8] {
      switch node {
      case .integer(let integer):
        return IDENTIFIERS.INTERGER.bytes + asn1LengthPrefixed(integer.bytes)
      case .bitString(let bits):
        return IDENTIFIERS.BITSTRING.bytes + asn1LengthPrefixed([0x00] + bits.bytes)
      case .octetString(let octet):
        return IDENTIFIERS.OCTETSTRING.bytes + asn1LengthPrefixed(octet.bytes)
      case .null:
        return IDENTIFIERS.NULL.bytes
      case .objectIdentifier(let oid):
        return IDENTIFIERS.OBJECTID.bytes + asn1LengthPrefixed(oid.bytes)
      case .sequence(let nodes):
        return IDENTIFIERS.SEQUENCE.bytes + asn1LengthPrefixed( nodes.reduce(into: Array<UInt8>(), { partialResult, node in
          partialResult += encode(node)
        }))
      }
    }
    
    /// Calculates and returns the ASN.1 length Prefix for a chunk of data
    private static func asn1LengthPrefix(_ bytes:[UInt8]) -> [UInt8] {
      if bytes.count >= 0x80 {
        var lengthAsBytes = withUnsafeBytes(of: bytes.count.bigEndian, Array<UInt8>.init)
        while lengthAsBytes.first == 0 { lengthAsBytes.removeFirst() }
        return [(0x80 + UInt8(lengthAsBytes.count))] + lengthAsBytes
      } else {
        return [UInt8(bytes.count)]
      }
    }
    
    /// Returns the provided bytes with the appropriate ASN.1 length prefix prepended
    private static func asn1LengthPrefixed(_ bytes:[UInt8]) -> [UInt8] {
      asn1LengthPrefix(bytes) + bytes
    }
  }
}

fileprivate func printNode(_ node:ASN1.Parser.Node, level:Int) -> String {
  var str:[String] = []
  let prefix = String(repeating: "\t", count: level)
  switch node {
  case .integer(let int):
    str.append("\(prefix)Integer: \(int.toHexString())")
  case .bitString(let bs):
    str.append("\(prefix)BitString: \(bs.toHexString())")
  case .null:
    str.append("\(prefix)NULL")
  case .objectIdentifier(let oid):
    str.append("\(prefix)ObjectID: \(oid.toHexString())")
  case .octetString(let os):
    str.append("\(prefix)OctetString: \(os.toHexString())")
  case .sequence(let nodes):
    nodes.forEach { str.append(printNode($0, level: level + 1)) }
  }
  return str.joined(separator: "\n")
}


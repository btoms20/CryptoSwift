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

//  PKCS is a group of public-key cryptography standards devised
//  and published by RSA Security Inc, starting in the early 1990s.
//

struct PKCS1v15Padding: PaddingProtocol {
  enum Error: Swift.Error {
    case invalidPaddingValue
  }

  init() {
  }

  @inlinable
  func add(to bytes: Array<UInt8>, blockSize: Int) -> Array<UInt8> {
    if blockSize < bytes.count + 11 { return [] }
    
    let r = blockSize - bytes.count - 3
    return [0x00, 0x01] + Array<UInt8>(repeating: 0xFF, count: r) + [0x00] + bytes
  }

  @inlinable
  func remove(from bytes: Array<UInt8>, blockSize _: Int?) -> Array<UInt8> {
    guard !bytes.isEmpty else {
      return bytes
    }

    assert(!bytes.isEmpty, "Need bytes to remove padding")
 
    guard bytes.prefix(2) == [0x00, 0x01] else {
      return bytes
    }
      
      let padding = (bytes.dropFirst(2).firstIndex(of: 0x00) ?? bytes.count) + 2
      
    let finalLength = bytes.count - padding

    if finalLength < 0 {
      return bytes
    }
      
    if padding >= 1 {
      return Array(bytes[0..<finalLength])
    }
    return bytes
  }
}


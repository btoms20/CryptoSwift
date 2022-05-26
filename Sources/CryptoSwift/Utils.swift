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

@inlinable
func rotateLeft(_ value: UInt8, by: UInt8) -> UInt8 {
  ((value << by) & 0xff) | (value >> (8 - by))
}

@inlinable
func rotateLeft(_ value: UInt16, by: UInt16) -> UInt16 {
  ((value << by) & 0xffff) | (value >> (16 - by))
}

@inlinable
func rotateLeft(_ value: UInt32, by: UInt32) -> UInt32 {
  ((value << by) & 0xffffffff) | (value >> (32 - by))
}

@inlinable
func rotateLeft(_ value: UInt64, by: UInt64) -> UInt64 {
  (value << by) | (value >> (64 - by))
}

@inlinable
func rotateRight(_ value: UInt16, by: UInt16) -> UInt16 {
  (value >> by) | (value << (16 - by))
}

@inlinable
func rotateRight(_ value: UInt32, by: UInt32) -> UInt32 {
  (value >> by) | (value << (32 - by))
}

@inlinable
func rotateRight(_ value: UInt64, by: UInt64) -> UInt64 {
  ((value >> by) | (value << (64 - by)))
}

@inlinable
func reversed(_ uint8: UInt8) -> UInt8 {
  var v = uint8
  v = (v & 0xf0) >> 4 | (v & 0x0f) << 4
  v = (v & 0xcc) >> 2 | (v & 0x33) << 2
  v = (v & 0xaa) >> 1 | (v & 0x55) << 1
  return v
}

@inlinable
func reversed(_ uint32: UInt32) -> UInt32 {
  var v = uint32
  v = ((v >> 1) & 0x55555555) | ((v & 0x55555555) << 1)
  v = ((v >> 2) & 0x33333333) | ((v & 0x33333333) << 2)
  v = ((v >> 4) & 0x0f0f0f0f) | ((v & 0x0f0f0f0f) << 4)
  v = ((v >> 8) & 0x00ff00ff) | ((v & 0x00ff00ff) << 8)
  v = ((v >> 16) & 0xffff) | ((v & 0xffff) << 16)
  return v
}

@inlinable
func xor<T, V>(_ left: T, _ right: V) -> ArraySlice<UInt8> where T: RandomAccessCollection, V: RandomAccessCollection, T.Element == UInt8, T.Index == Int, V.Element == UInt8, V.Index == Int {
  return xor(left, right).slice
}

@inlinable
func xor<T, V>(_ left: T, _ right: V) -> Array<UInt8> where T: RandomAccessCollection, V: RandomAccessCollection, T.Element == UInt8, T.Index == Int, V.Element == UInt8, V.Index == Int {
  let length = Swift.min(left.count, right.count)

  let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
  buf.initialize(repeating: 0, count: length)
  defer {
    buf.deinitialize(count: length)
    buf.deallocate()
  }

  // xor
  for i in 0..<length {
    buf[i] = left[left.startIndex.advanced(by: i)] ^ right[right.startIndex.advanced(by: i)]
  }

  return Array(UnsafeBufferPointer(start: buf, count: length))
}

/**
 ISO/IEC 9797-1 Padding method 2.
 Add a single bit with value 1 to the end of the data.
 If necessary add bits with value 0 to the end of the data until the padded data is a multiple of blockSize.
 - parameters:
 - blockSize: Padding size in bytes.
 - allowance: Excluded trailing number of bytes.
 */
@inline(__always) @inlinable
func bitPadding(to data: inout Array<UInt8>, blockSize: Int, allowance: Int = 0) {
  let msgLength = data.count
  // Step 1. Append Padding Bits
  // append one bit (UInt8 with one bit) to message
  data.append(0x80)

  // Step 2. append "0" bit until message length in bits ≡ 448 (mod 512)
  let max = blockSize - allowance // 448, 986
  if msgLength % blockSize < max { // 448
    data += Array<UInt8>(repeating: 0, count: max - 1 - (msgLength % blockSize))
  } else {
    data += Array<UInt8>(repeating: 0, count: blockSize + max - 1 - (msgLength % blockSize))
  }
}


// MARK: Chunks of Collection (used in exporting PEM strings)
public struct ChunksOfCountCollection<Base: Collection> {
  public typealias Element = Base.SubSequence
  
  @usableFromInline
  internal let base: Base
  
  @usableFromInline
  internal let chunkCount: Int
  
  @usableFromInline
  internal var endOfFirstChunk: Base.Index

  ///  Creates a view instance that presents the elements of `base` in
  ///  `SubSequence` chunks of the given count.
  ///
  /// - Complexity: O(*n*), because the start index is pre-computed.
  @inlinable
  internal init(_base: Base, _chunkCount: Int) {
    self.base = _base
    self.chunkCount = _chunkCount
    
    // Compute the start index upfront in order to make start index a O(1)
    // lookup.
    self.endOfFirstChunk = _base.index(
      _base.startIndex, offsetBy: _chunkCount,
      limitedBy: _base.endIndex
    ) ?? _base.endIndex
  }
}

extension Collection {
  /// Returns a `ChunksOfCountCollection<Self>` view presenting the elements in
  /// chunks with count of the given count parameter.
  ///
  /// - Parameter count: The size of the chunks. If the `count` parameter is
  ///   evenly divided by the count of the base `Collection` all the chunks will
  ///   have the count equals to size. Otherwise, the last chunk will contain
  ///   the remaining elements.
  ///
  ///     let c = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  ///     print(c.chunks(ofCount: 5).map(Array.init))
  ///     // [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]]
  ///
  ///     print(c.chunks(ofCount: 3).map(Array.init))
  ///     // [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10]]
  ///
  /// - Complexity: O(*n*), because the start index is pre-computed.
  @inlinable
  public func chunks(ofCount count: Int) -> ChunksOfCountCollection<Self> {
    precondition(count > 0, "Cannot chunk with count <= 0!")
    return ChunksOfCountCollection(_base: self, _chunkCount: count)
  }
}

extension ChunksOfCountCollection: Collection {
  public struct Index {
    @usableFromInline
    internal let baseRange: Range<Base.Index>
    
    @inlinable
    internal init(_baseRange: Range<Base.Index>) {
      self.baseRange = _baseRange
    }
  }

  /// - Complexity: O(1)
  @inlinable
  public var startIndex: Index {
    Index(_baseRange: base.startIndex..<endOfFirstChunk)
  }
  
  @inlinable
  public var endIndex: Index {
    Index(_baseRange: base.endIndex..<base.endIndex)
  }
  
  /// - Complexity: O(1)
  @inlinable
  public subscript(i: Index) -> Element {
    precondition(i != endIndex, "Index out of range")
    return base[i.baseRange]
  }
  
  @inlinable
  public func index(after i: Index) -> Index {
    precondition(i != endIndex, "Advancing past end index")
    let baseIdx = base.index(
      i.baseRange.upperBound, offsetBy: chunkCount,
      limitedBy: base.endIndex
    ) ?? base.endIndex
    return Index(_baseRange: i.baseRange.upperBound..<baseIdx)
  }
}

extension ChunksOfCountCollection.Index: Comparable {
  @inlinable
  public static func == (lhs: ChunksOfCountCollection.Index,
                         rhs: ChunksOfCountCollection.Index) -> Bool {
    lhs.baseRange.lowerBound == rhs.baseRange.lowerBound
  }
  
  @inlinable
  public static func < (lhs: ChunksOfCountCollection.Index,
                        rhs: ChunksOfCountCollection.Index) -> Bool {
    lhs.baseRange.lowerBound < rhs.baseRange.lowerBound
  }
}

extension ChunksOfCountCollection.Index: Hashable where Base.Index: Hashable {}

extension ChunksOfCountCollection: LazySequenceProtocol, LazyCollectionProtocol
  where Base: LazySequenceProtocol {}


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
    /// Failed to calculate the inverse e and phi
    case invalidInverseNotCoprimes
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
  private let primes: (p: BigUInteger, q: BigUInteger)?

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
  public convenience init(keySize: Int, threads:Int = 1) throws {
    // Generate prime numbers
    //let p = BigUInteger.generatePrime(keySize / 2)
    //let q = BigUInteger.generatePrime(keySize / 2)
    let primes = MultithreadedPrimeGeneration(numberOfPrimes: 2, size: keySize / 2, threadCount: threads).generate()
    let p = primes.first!
    let q = primes.last!
    
    // Calculate modulus
    let n = p * q

    // Calculate public and private exponent
    let e: BigUInteger = 65537
    let phi = (p - 1) * (q - 1)
    guard let d = e.inverse(phi) else {
      throw RSA.Error.invalidInverseNotCoprimes
    }

    // Initialize
    self.init(n: n, e: e, d: d, p: p, q: q)
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

  // TODO: Add initializer from PEM (ASN.1 with DER header) (See #892)

  // TODO: Add export to PEM (ASN.1 with DER header) (See #892)
}

// MARK: Cipher

extension RSA: Cipher {

  @inlinable
  public func encrypt(_ bytes: ArraySlice<UInt8>) throws -> Array<UInt8> {
    // Calculate encrypted data
    return BigUInteger(Data(bytes)).power(self.e, modulus: self.n).serialize().bytes
  }

  @inlinable
  public func decrypt(_ bytes: ArraySlice<UInt8>) throws -> Array<UInt8> {
    // Check for Private Exponent presence
    guard let d = d else {
      throw RSA.Error.noPrivateKey
    }

    // Calculate decrypted data
    return BigUInteger(Data(bytes)).power(d, modulus: self.n).serialize().bytes
  }
}

// MARK: CS.BigUInt extension

//extension BigUInteger {

//  public static func generatePrime(_ width: Int) -> BigUInteger {
//    // Note: Need to find a better way to generate prime numbers
//    while true {
//      var random = BigUInteger.randomInteger(withExactWidth: width)
//      random |= BigUInteger(1)
//      if random.isPrime() {
//        return random
//      }
//    }
//  }
  
  internal class MultithreadedPrimeGeneration {
    let numberOfPrimes:Int
    let size:Int
    let threadCount:Int
    
    private var group:[Thread] = []
    private var isDone:Bool = false
    private var primesGenerated:[BigUInteger] {
      didSet {
        if primesGenerated.count >= numberOfPrimes {
          self.isDone = true
          self.group.forEach { $0.cancel() }
          self.group = []
        }
      }
    }
    
    init(numberOfPrimes:Int = 2, size:Int, threadCount:Int = 1) {
      self.numberOfPrimes = numberOfPrimes
      self.size = size
      self.threadCount = threadCount
      self.primesGenerated = []
    }
    
    public func generate() -> [BigUInteger] {
      guard threadCount != 1 else {
        print("Single Thread")
        return (0..<numberOfPrimes).map { _ in generatePrime(self.size) }
      }
      print("Launching [\(threadCount)] Threads in search of Primes!")
      self.startMulti()
      while !isDone { usleep(100_000) }
      usleep(250_000)
      return Array(primesGenerated.prefix(numberOfPrimes))
    }
    
    public func startMulti() {
      group = (0..<threadCount).map { _ in
        Thread {
          while !self.isDone {
            if let prime = self.searchForPrime(self.size) { self.primesGenerated.append(prime) }
          }
        }
      }
      group.forEach { $0.start() }
    }
    
    private func searchForPrime(_ width: Int) -> BigUInteger? {
      while !self.isDone {
        var random = BigUInteger.randomInteger(withExactWidth: width)
        random |= BigUInteger(1)
        if random.isPrime() {
          return random
        }
      }
      return nil
    }
    
    private func generatePrime(_ width: Int) -> BigUInteger {
      while true {
        var random = BigUInteger.randomInteger(withExactWidth: width)
        random |= BigUInteger(1)
        if random.isPrime() {
          return random
        }
      }
    }
  }
  
//  private enum System {
//      /// A utility function that returns an estimate of the number of *logical* cores
//      /// on the system.
//      ///
//      /// This value can be used to help provide an estimate of how many threads to use with
//      /// the `MultiThreadedEventLoopGroup`. The exact ratio between this number and the number
//      /// of threads to use is a matter for the programmer, and can be determined based on the
//      /// specific execution behaviour of the program.
//      ///
//      /// - returns: The logical core count on the system.
//      public static var coreCount: Int {
//  #if os(Windows)
//          var dwLength: DWORD = 0
//          _ = GetLogicalProcessorInformation(nil, &dwLength)
//
//          let alignment: Int =
//              MemoryLayout<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>.alignment
//          let pBuffer: UnsafeMutableRawPointer =
//              UnsafeMutableRawPointer.allocate(byteCount: Int(dwLength),
//                                               alignment: alignment)
//          defer {
//              pBuffer.deallocate()
//          }
//
//          let dwSLPICount: Int =
//              Int(dwLength) / MemoryLayout<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>.stride
//          let pSLPI: UnsafeMutablePointer<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> =
//              pBuffer.bindMemory(to: SYSTEM_LOGICAL_PROCESSOR_INFORMATION.self,
//                                 capacity: dwSLPICount)
//
//          let bResult: Bool = GetLogicalProcessorInformation(pSLPI, &dwLength)
//          precondition(bResult, "GetLogicalProcessorInformation: \(GetLastError())")
//
//          return UnsafeBufferPointer<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>(start: pSLPI,
//                                                                           count: dwSLPICount)
//              .filter { $0.Relationship == RelationProcessorCore }
//              .map { $0.ProcessorMask.nonzeroBitCount }
//              .reduce(0, +)
//  #elseif os(Linux) || os(Android)
////          if let quota = Linux.coreCount(quota: Linux.cfsQuotaPath, period: Linux.cfsPeriodPath) {
////              return quota
////          } else if let cpusetCount = Linux.coreCount(cpuset: Linux.cpuSetPath) {
////              return cpusetCount
////          } else {
//              return sysconf(CInt(_SC_NPROCESSORS_ONLN))
////          }
//  #else
//          return sysconf(CInt(_SC_NPROCESSORS_ONLN))
//  #endif
//      }
//  }
  
//}


//#if os(Linux) || os(Android)
//import CNIOLinux
//enum Linux {
//    static let cfsQuotaPath = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
//    static let cfsPeriodPath = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
//    static let cpuSetPath = "/sys/fs/cgroup/cpuset/cpuset.cpus"
//
//    private static func firstLineOfFile(path: String) throws -> Substring {
//        let fh = try NIOFileHandle(path: path)
//        defer { try! fh.close() }
//        // linux doesn't properly report /sys/fs/cgroup/* files lengths so we use a reasonable limit
//        var buf = ByteBufferAllocator().buffer(capacity: 1024)
//        try buf.writeWithUnsafeMutableBytes(minimumWritableBytes: buf.capacity) { ptr in
//            let res = try fh.withUnsafeFileDescriptor { fd -> CoreIOResult<ssize_t> in
//                return try SystemCalls.read(descriptor: fd, pointer: ptr.baseAddress!, size: ptr.count)
//            }
//            switch res {
//            case .processed(let n):
//                return n
//            case .wouldBlock:
//                preconditionFailure("read returned EWOULDBLOCK despite a blocking fd")
//            }
//        }
//        return String(buffer: buf).prefix(while: { $0 != "\n" })
//    }
//
//    private static func countCoreIds(cores: Substring) -> Int {
//        let ids = cores.split(separator: "-", maxSplits: 1)
//        guard
//            let first = ids.first.flatMap({ Int($0, radix: 10) }),
//            let last = ids.last.flatMap({ Int($0, radix: 10) }),
//            last >= first
//        else { preconditionFailure("cpuset format is incorrect") }
//        return 1 + last - first
//    }
//
//    static func coreCount(cpuset cpusetPath: String) -> Int? {
//        guard
//            let cpuset = try? firstLineOfFile(path: cpusetPath).split(separator: ","),
//            !cpuset.isEmpty
//        else { return nil }
//        return cpuset.map(countCoreIds).reduce(0, +)
//    }
//
//    static func coreCount(quota quotaPath: String,  period periodPath: String) -> Int? {
//        guard
//            let quota = try? Int(firstLineOfFile(path: quotaPath)),
//            quota > 0
//        else { return nil }
//        guard
//            let period = try? Int(firstLineOfFile(path: periodPath)),
//            period > 0
//        else { return nil }
//        return (quota - 1 + period) / period // always round up if fractional CPU quota requested
//    }
//}
//#endif

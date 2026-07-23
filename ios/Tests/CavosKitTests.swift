import XCTest
import Security
@testable import CavosKit

final class CavosKitTests: XCTestCase {
  func testPersistentSigningAndDeletion() throws {
    let alias = "test-\(UUID().uuidString)"
    let first = try KeyStore.shared.getOrCreate(alias: alias, operation: "sign")
    let second = try KeyStore.shared.getOrCreate(alias: alias, operation: "sign")
    XCTAssertEqual(first["publicKey"], second["publicKey"])

    let message = Data("cavos-native-vector".utf8)
    let signature = try KeyStore.shared.sign(alias: alias, payload: message)
    let publicData = Data(base64Encoded: first["publicKey"]!)!
    let publicKey = SecKeyCreateWithData(publicData as CFData, [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits: 256,
    ] as CFDictionary, nil)!
    XCTAssertTrue(SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
      message as CFData, signature as CFData, nil))

    KeyStore.shared.delete(alias: alias)
    let replacement = try KeyStore.shared.getOrCreate(alias: alias, operation: "sign")
    XCTAssertNotEqual(first["publicKey"], replacement["publicKey"])
    KeyStore.shared.delete(alias: alias)
  }

  func testEcdhMatchesPeer() throws {
    let alias = "test-\(UUID().uuidString)"
    let native = try KeyStore.shared.getOrCreate(alias: alias, operation: "unwrap")
    let peer = try makePeer()
    let peerPublic = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(peer)!, nil)! as Data
    let nativeSecret = try KeyStore.shared.sharedSecret(alias: alias, peer: peerPublic)

    let nativePublicData = Data(base64Encoded: native["publicKey"]!)!
    let nativePublic = SecKeyCreateWithData(nativePublicData as CFData, [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits: 256,
    ] as CFDictionary, nil)!
    let peerSecret = SecKeyCopyKeyExchangeResult(peer, .ecdhKeyExchangeStandard,
      nativePublic, [:] as CFDictionary, nil)! as Data
    XCTAssertEqual(nativeSecret, peerSecret)
    KeyStore.shared.delete(alias: alias)
  }

  private func makePeer() throws -> SecKey {
    var error: Unmanaged<CFError>?
    let key = SecKeyCreateRandomKey([
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
    ] as CFDictionary, &error)
    if let key { return key }
    throw error!.takeRetainedValue()
  }
}

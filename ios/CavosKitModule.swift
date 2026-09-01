import ExpoModulesCore
import Security
import CryptoKit
import AuthenticationServices
import UIKit

public final class CavosKitModule: Module {
  public func definition() -> ModuleDefinition {
    Name("CavosKit")

    AsyncFunction("getOrCreateSigningKey") { (alias: String) in
      try KeyStore.shared.getOrCreate(alias: alias, operation: "sign")
    }
    AsyncFunction("sign") { (alias: String, payload: String) in
      try KeyStore.shared.sign(alias: alias, payload: Data(base64Encoded: payload)!)
        .base64EncodedString()
    }
    AsyncFunction("getOrCreateUnwrapKey") { (alias: String) in
      try KeyStore.shared.getOrCreate(alias: alias, operation: "unwrap")
    }
    AsyncFunction("deriveSharedSecret") { (alias: String, peer: String) in
      try KeyStore.shared.sharedSecret(alias: alias, peer: Data(base64Encoded: peer)!)
        .base64EncodedString()
    }
    AsyncFunction("deleteKeys") { (alias: String) in
      KeyStore.shared.delete(alias: alias)
    }
    AsyncFunction("getCapabilities") {
      #if targetEnvironment(simulator)
      return [
        "signingKey": "development", "ecdhKey": "development",
        "passkey": true, "passkeyPrf": false,
      ] as [String: Any]
      #else
      let enclave = SecureEnclave.isAvailable
      return [
        "signingKey": enclave ? "secure-enclave" : "os-protected",
        "ecdhKey": enclave ? "secure-enclave" : "os-protected",
        "passkey": true,
        "passkeyPrf": {
          if #available(iOS 18.0, *) { return true }
          return false
        }()
      ] as [String: Any]
      #endif
    }
    AsyncFunction("randomBytes") { (length: Int) in
      var bytes = [UInt8](repeating: 0, count: length)
      guard SecRandomCopyBytes(kSecRandomDefault, length, &bytes) == errSecSuccess else {
        throw CavosNativeError("Secure random generation failed")
      }
      return Data(bytes).base64EncodedString()
    }
    AsyncFunction("getStoredValue") { (key: String) -> String? in
      UserDefaults.standard.string(forKey: "cavos.\(Self.digest(key))")
    }
    AsyncFunction("setStoredValue") { (key: String, value: String?) in
      UserDefaults.standard.set(value, forKey: "cavos.\(Self.digest(key))")
    }
    AsyncFunction("createPasskey") { (json: String, promise: Promise) in
      Task { @MainActor in
        do {
          promise.resolve(try await PasskeyBridge.shared.create(json: json))
        } catch {
          promise.reject(error)
        }
      }
    }.runOnQueue(.main)
    AsyncFunction("getPasskey") { (json: String, promise: Promise) in
      Task { @MainActor in
        do {
          promise.resolve(try await PasskeyBridge.shared.get(json: json))
        } catch {
          promise.reject(error)
        }
      }
    }.runOnQueue(.main)

    /// Native ed25519 signing that never exposes the seed or DEK to JavaScript.
    ///
    /// Performs the full unwrap → sign flow in native code:
    /// 1. ECDH with device key to get shared secret
    /// 2. HKDF to derive KEK from shared secret
    /// 3. AES-GCM decrypt to unwrap DEK
    /// 4. AES-GCM decrypt to open control seed
    /// 5. Ed25519 sign with control seed
    /// 6. Return ONLY { signature, publicKey } — seed is wiped, never crosses bridge
    ///
    /// This is the secure spend path for React Native: no biometric prompt (silent),
    /// but the private key material stays in the native process.
    AsyncFunction("unwrapControlAndSign") { (alias: String, deviceWrap: String, ciphertext: String, data: String) in
      try KeyStore.shared.unwrapControlAndSign(
        alias: alias,
        deviceWrap: Data(base64Encoded: deviceWrap)!,
        ciphertext: Data(base64Encoded: ciphertext)!,
        data: Data(base64Encoded: data)!
      )
    }

    /// Get the ed25519 public key for a control seed wrapped to this device.
    /// Returns the public key without exposing the seed to JavaScript.
    AsyncFunction("unwrapControlPublicKey") { (alias: String, deviceWrap: String, ciphertext: String) in
      try KeyStore.shared.unwrapControlPublicKey(
        alias: alias,
        deviceWrap: Data(base64Encoded: deviceWrap)!,
        ciphertext: Data(base64Encoded: ciphertext)!
      )
    }
  }

  fileprivate static func digest(_ value: String) -> String {
    SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
  }
}

private struct CavosNativeError: Error, LocalizedError {
  let message: String
  init(_ message: String) { self.message = message }
  var errorDescription: String? { message }
}

final class KeyStore {
  static let shared = KeyStore()

  func getOrCreate(alias: String, operation: String) throws -> [String: String] {
    let tag = tagFor(alias, operation)
    let key = try load(tag) ?? create(tag)
    guard let publicKey = SecKeyCopyPublicKey(key),
          let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
      throw CavosNativeError("Could not export public key")
    }
    let level = UserDefaults.standard.string(forKey: "cavos.level.\(tag.base64EncodedString())")
      ?? "os-protected"
    return ["publicKey": data.base64EncodedString(), "securityLevel": level]
  }

  func sign(alias: String, payload: Data) throws -> Data {
    let key = try required(alias, "sign")
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error) else {
      if let error { throw error.takeRetainedValue() }
      throw CavosNativeError("Signing failed")
    }
    return signature as Data
  }

  func sharedSecret(alias: String, peer: Data) throws -> Data {
    let key = try required(alias, "unwrap")
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits: 256,
    ]
    var error: Unmanaged<CFError>?
    guard let peerKey = SecKeyCreateWithData(peer as CFData, attributes as CFDictionary, &error),
          let secret = SecKeyCopyKeyExchangeResult(key, .ecdhKeyExchangeStandard, peerKey, [:] as CFDictionary, &error) else {
      if let error { throw error.takeRetainedValue() }
      throw CavosNativeError("ECDH failed")
    }
    return secret as Data
  }

  /// Native ed25519 signing — the seed never leaves this function.
  ///
  /// `deviceWrap`: ephPubCompressed(33) || nonce(12) || AES-GCM(kek, dek)
  /// `ciphertext`: nonce(12) || AES-GCM(dek, controlSeed)
  /// `data`: the payload to sign (typically a transaction hash)
  ///
  /// Returns { "signature": base64, "publicKey": base64 }
  func unwrapControlAndSign(alias: String, deviceWrap: Data, ciphertext: Data, data: Data) throws -> [String: String] {
    // 1. Extract ephemeral public key and wrapped DEK from device wrap
    guard deviceWrap.count > 33 + 12 + 16 else {
      throw CavosNativeError("Device wrap too short")
    }
    let ephPubCompressed = deviceWrap.prefix(33)
    let wrappedDEK = deviceWrap.dropFirst(33)

    // 2. ECDH to get shared secret X
    let sharedX = try ecdhSharedX(alias: alias, ephPubCompressed: ephPubCompressed)

    // 3. Derive KEK using HKDF
    let kek = try eciesKEK(sharedX: sharedX, ephPubCompressed: ephPubCompressed)

    // 4. Unwrap DEK (AES-GCM decrypt)
    let dek = try aesGcmDecrypt(ciphertext: wrappedDEK, key: kek)

    // 5. Open control seed from ciphertext
    var controlSeed = try aesGcmDecrypt(ciphertext: ciphertext, key: dek)
    defer {
      // Wipe the seed from memory as soon as we're done
      controlSeed.resetBytes(in: controlSeed.startIndex..<controlSeed.endIndex)
    }

    guard controlSeed.count == 32 else {
      throw CavosNativeError("Invalid control seed length")
    }

    // 6. Sign with ed25519
    let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: controlSeed)
    let signature = try signingKey.signature(for: data)
    let publicKey = signingKey.publicKey.rawRepresentation

    return [
      "signature": Data(signature).base64EncodedString(),
      "publicKey": publicKey.base64EncodedString(),
    ]
  }

  /// Get ed25519 public key without exposing seed to JS.
  func unwrapControlPublicKey(alias: String, deviceWrap: Data, ciphertext: Data) throws -> [String: String] {
    guard deviceWrap.count > 33 + 12 + 16 else {
      throw CavosNativeError("Device wrap too short")
    }
    let ephPubCompressed = deviceWrap.prefix(33)
    let wrappedDEK = deviceWrap.dropFirst(33)

    let sharedX = try ecdhSharedX(alias: alias, ephPubCompressed: ephPubCompressed)
    let kek = try eciesKEK(sharedX: sharedX, ephPubCompressed: ephPubCompressed)
    let dek = try aesGcmDecrypt(ciphertext: wrappedDEK, key: kek)

    var controlSeed = try aesGcmDecrypt(ciphertext: ciphertext, key: dek)
    defer {
      controlSeed.resetBytes(in: controlSeed.startIndex..<controlSeed.endIndex)
    }

    guard controlSeed.count == 32 else {
      throw CavosNativeError("Invalid control seed length")
    }

    let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: controlSeed)
    return ["publicKey": signingKey.publicKey.rawRepresentation.base64EncodedString()]
  }

  /// ECDH with the device's P-256 key, returning only the X coordinate (32 bytes).
  private func ecdhSharedX(alias: String, ephPubCompressed: Data) throws -> Data {
    // Decompress the P-256 point for Security framework
    let uncompressed = try decompressP256(ephPubCompressed)
    let sharedPoint = try sharedSecret(alias: alias, peer: uncompressed)
    // sharedPoint is the full point; we need just the X coordinate (32 bytes)
    return sharedPoint.prefix(32)
  }

  /// Derive ECIES KEK: HKDF-SHA256(sharedX, salt=ephPubCompressed, info="cavos-stellar-dek-ecies", len=32)
  private func eciesKEK(sharedX: Data, ephPubCompressed: Data) throws -> Data {
    let info = Data("cavos-stellar-dek-ecies".utf8)
    let key = SymmetricKey(data: sharedX)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      salt: ephPubCompressed,
      info: info,
      outputByteCount: 32
    )
    return derived.withUnsafeBytes { Data($0) }
  }

  /// AES-256-GCM decrypt. Input: nonce(12) || ciphertext || tag(16)
  private func aesGcmDecrypt(ciphertext: Data, key: Data) throws -> Data {
    guard ciphertext.count > 12 + 16 else {
      throw CavosNativeError("Ciphertext too short for AES-GCM")
    }
    let nonce = ciphertext.prefix(12)
    let sealed = ciphertext.dropFirst(12)

    let aesKey = SymmetricKey(data: key)
    let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
    return try AES.GCM.open(sealedBox, using: aesKey)
  }

  /// Decompress a SEC1 compressed P-256 point (33 bytes) to uncompressed (65 bytes).
  /// The Security framework requires uncompressed format for ECDH.
  private func decompressP256(_ compressed: Data) throws -> Data {
    guard compressed.count == 33 else {
      throw CavosNativeError("Invalid compressed point length")
    }
    let prefix = compressed[compressed.startIndex]
    guard prefix == 0x02 || prefix == 0x03 else {
      throw CavosNativeError("Invalid compression prefix")
    }
    let x = compressed.dropFirst()

    // P-256 field prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    // y^2 = x^3 - 3x + b  (mod p)
    // b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

    // Use CryptoKit to decompress by creating a P256 public key
    // CryptoKit accepts compressed format directly
    do {
      let p256Key = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressed)
      return p256Key.x963Representation
    } catch {
      throw CavosNativeError("Failed to decompress P-256 point: \(error)")
    }
  }

  func delete(alias: String) {
    for operation in ["sign", "unwrap"] {
      let tag = tagFor(alias, operation)
      SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag] as CFDictionary)
    }
  }

  private func required(_ alias: String, _ operation: String) throws -> SecKey {
    let tag = tagFor(alias, operation)
    guard let key = try load(tag) else { throw CavosNativeError("Key not found") }
    return key
  }

  private func create(_ tag: Data) throws -> SecKey {
    if SecureEnclave.isAvailable, let key = try? createKey(tag, secureEnclave: true) {
      UserDefaults.standard.set("secure-enclave", forKey: "cavos.level.\(tag.base64EncodedString())")
      return key
    }
    let key = try createKey(tag, secureEnclave: false)
    #if targetEnvironment(simulator)
    UserDefaults.standard.set("development", forKey: "cavos.level.\(tag.base64EncodedString())")
    #else
    UserDefaults.standard.set("os-protected", forKey: "cavos.level.\(tag.base64EncodedString())")
    #endif
    return key
  }

  private func createKey(_ tag: Data, secureEnclave: Bool) throws -> SecKey {
    var privateAttrs: [CFString: Any] = [
      kSecAttrIsPermanent: true,
      kSecAttrApplicationTag: tag,
      kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    if secureEnclave {
      privateAttrs[kSecAttrAccessControl] = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil
      )!
      privateAttrs.removeValue(forKey: kSecAttrAccessible)
    }
    var attrs: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecPrivateKeyAttrs: privateAttrs,
    ]
    if secureEnclave { attrs[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave }
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
      throw error!.takeRetainedValue()
    }
    return key
  }

  private func load(_ tag: Data) throws -> SecKey? {
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecAttrApplicationTag: tag,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw CavosNativeError("Keychain error \(status)") }
    return (item as! SecKey)
  }

  private func tagFor(_ alias: String, _ operation: String) -> Data {
    Data("xyz.cavos.\(operation).\(CavosKitModule.digest(alias))".utf8)
  }
}

@MainActor private final class PasskeyBridge: NSObject, ASAuthorizationControllerDelegate,
  ASAuthorizationControllerPresentationContextProviding {
  static let shared = PasskeyBridge()
  private var continuation: CheckedContinuation<[String: Any], Error>?
  private var registration = false

  func create(json: String) async throws -> [String: Any] {
    let options = try parse(json)
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options["rpId"] as! String)
    let request = provider.createCredentialRegistrationRequest(
      challenge: Data(base64Encoded: options["challenge"] as! String)!,
      name: options["userName"] as! String,
      userID: Data(base64Encoded: options["userId"] as! String)!
    )
    request.displayName = options["displayName"] as? String
    if #available(iOS 18.0, *), let saltValue = options["prfSalt"] as? String,
       let salt = Data(base64Encoded: saltValue) {
      request.prf = .inputValues(.init(saltInput1: salt, saltInput2: nil))
    }
    registration = true
    return try await perform(request)
  }

  func get(json: String) async throws -> [String: Any] {
    let options = try parse(json)
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options["rpId"] as! String)
    let request = provider.createCredentialAssertionRequest(challenge: Data(base64Encoded: options["challenge"] as! String)!)
    if #available(iOS 18.0, *), let saltValue = options["prfSalt"] as? String,
       let salt = Data(base64Encoded: saltValue) {
      request.prf = .inputValues(.init(saltInput1: salt, saltInput2: nil))
    }
    registration = false
    return try await perform(request)
  }

  private func perform(_ request: ASAuthorizationRequest) async throws -> [String: Any] {
    try await withCheckedThrowingContinuation { continuation in
      self.continuation = continuation
      let controller = ASAuthorizationController(authorizationRequests: [request])
      controller.delegate = self
      controller.presentationContextProvider = self
      controller.performRequests()
    }
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    if let value = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
      guard let attestation = value.rawAttestationObject,
            let point = extractP256(attestation) else {
        continuation?.resume(throwing: CavosNativeError("Passkey attestation has no P-256 key")); return
      }
      var response: [String: Any] = [
        "credentialId": value.credentialID.base64EncodedString(),
        "publicKey": point.base64EncodedString(),
      ]
      if #available(iOS 18.0, *), let first = value.prf?.first {
        response["prfSecret"] = first.withUnsafeBytes { Data($0).base64EncodedString() }
      }
      continuation?.resume(returning: response)
    } else if let value = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
      var response: [String: Any] = [
        "authenticatorData": value.rawAuthenticatorData.base64EncodedString(),
        "clientDataJSON": value.rawClientDataJSON.base64EncodedString(),
        "signature": value.signature.base64EncodedString(),
      ]
      if #available(iOS 18.0, *), let first = value.prf?.first {
        response["prfSecret"] = first.withUnsafeBytes { Data($0).base64EncodedString() }
      }
      continuation?.resume(returning: response)
    } else {
      continuation?.resume(throwing: CavosNativeError("Unexpected passkey response"))
    }
    continuation = nil
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
    continuation?.resume(throwing: error); continuation = nil
  }

  func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
    UIApplication.shared.connectedScenes
      .compactMap { ($0 as? UIWindowScene)?.windows.first(where: { $0.isKeyWindow }) }
      .first ?? ASPresentationAnchor()
  }

  private func parse(_ json: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
  }

  /** Extract COSE -2/-3 byte strings from the attested credential data. */
  private func extractP256(_ attestation: Data) -> Data? {
    let bytes = [UInt8](attestation)
    for i in 0..<(max(0, bytes.count - 70)) where bytes[i] == 0x21 && bytes[i+1] == 0x58 && bytes[i+2] == 0x20 {
      let x = Data(bytes[(i+3)..<(i+35)])
      for j in (i+35)..<(min(bytes.count - 34, i + 80)) where bytes[j] == 0x22 && bytes[j+1] == 0x58 && bytes[j+2] == 0x20 {
        return Data([0x04]) + x + Data(bytes[(j+3)..<(j+35)])
      }
    }
    return nil
  }
}

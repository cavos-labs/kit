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

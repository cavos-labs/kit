package xyz.cavos.kit

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class CavosKitModule : Module() {
  private val context get() = requireNotNull(appContext.reactContext)
  private val keys by lazy { NativeKeys(context.getSharedPreferences("cavos-kit-keys", 0)) }

  override fun definition() = ModuleDefinition {
    Name("CavosKit")

    AsyncFunction("getOrCreateSigningKey") { alias: String -> keys.signingKey(alias) }
    AsyncFunction("sign") { alias: String, payload: String ->
      b64(keys.sign(alias, unb64(payload)))
    }
    AsyncFunction("getOrCreateUnwrapKey") { alias: String -> keys.unwrapKey(alias) }
    AsyncFunction("deriveSharedSecret") { alias: String, peer: String ->
      b64(keys.sharedSecret(alias, unb64(peer)))
    }
    AsyncFunction("deleteKeys") { alias: String -> keys.delete(alias) }
    AsyncFunction("getCapabilities") {
      mapOf(
        "signingKey" to keys.bestSecurityLevel(),
        "ecdhKey" to keys.bestEcdhSecurityLevel(),
        "passkey" to true,
        "passkeyPrf" to false,
      )
    }
    AsyncFunction("randomBytes") { length: Int ->
      ByteArray(length).also { SecureRandom().nextBytes(it) }.let(::b64)
    }
    AsyncFunction("getStoredValue") { key: String ->
      context.getSharedPreferences("cavos-kit", 0).getString(digest(key), null)
    }
    AsyncFunction("setStoredValue") { key: String, value: String? ->
      context.getSharedPreferences("cavos-kit", 0).edit().apply {
        if (value == null) remove(digest(key)) else putString(digest(key), value)
      }.apply()
    }
    AsyncFunction("createPasskey") Coroutine { json: String -> createPasskey(json) }
    AsyncFunction("getPasskey") Coroutine { json: String -> getPasskey(json) }
  }

  private suspend fun createPasskey(json: String): Map<String, Any> = withContext(Dispatchers.Main) {
    val o = JSONObject(json)
    val requestJson = JSONObject().apply {
      put("rp", JSONObject().put("id", o.getString("rpId")).put("name", o.getString("rpName")))
      put("user", JSONObject().put("id", b64url(unb64(o.getString("userId"))))
        .put("name", o.getString("userName")).put("displayName", o.getString("displayName")))
      put("challenge", b64url(unb64(o.getString("challenge"))))
      put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
      put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
      put("attestation", "none")
      if (o.has("prfSalt")) put("extensions", JSONObject().put("prf", JSONObject()
        .put("eval", JSONObject().put("first", b64url(unb64(o.getString("prfSalt")))))))
    }.toString()
    val response = CredentialManager.create(context)
      .createCredential(context, CreatePublicKeyCredentialRequest(requestJson)) as CreatePublicKeyCredentialResponse
    val parsed = JSONObject(response.registrationResponseJson)
    val responseObject = parsed.getJSONObject("response")
    val point = extractP256(unb64url(responseObject.getString("attestationObject")))
      ?: error("Passkey attestation has no P-256 key")
    mutableMapOf<String, Any>(
      "credentialId" to b64(unb64url(parsed.getString("rawId"))),
      "publicKey" to b64(point),
    ).apply { readPrf(parsed)?.let { put("prfSecret", b64(it)) } }
  }

  private suspend fun getPasskey(json: String): Map<String, Any> = withContext(Dispatchers.Main) {
    val o = JSONObject(json)
    val requestJson = JSONObject().apply {
      put("rpId", o.getString("rpId"))
      put("challenge", b64url(unb64(o.getString("challenge"))))
      put("allowCredentials", JSONArray())
      put("userVerification", o.optString("userVerification", "preferred"))
      if (o.has("prfSalt")) put("extensions", JSONObject().put("prf", JSONObject()
        .put("eval", JSONObject().put("first", b64url(unb64(o.getString("prfSalt")))))))
    }.toString()
    val result = CredentialManager.create(context).getCredential(
      context,
      GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)))
    ).credential as PublicKeyCredential
    val parsed = JSONObject(result.authenticationResponseJson)
    val response = parsed.getJSONObject("response")
    mutableMapOf<String, Any>(
      "authenticatorData" to b64(unb64url(response.getString("authenticatorData"))),
      "clientDataJSON" to b64(unb64url(response.getString("clientDataJSON"))),
      "signature" to b64(unb64url(response.getString("signature"))),
    ).apply { readPrf(parsed)?.let { put("prfSecret", b64(it)) } }
  }

  private fun readPrf(json: JSONObject): ByteArray? = try {
    unb64url(json.getJSONObject("clientExtensionResults").getJSONObject("prf")
      .getJSONObject("results").getString("first"))
  } catch (_: Exception) { null }
}

internal class NativeKeys(private val prefs: android.content.SharedPreferences) {
  private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  fun signingKey(id: String): Map<String, String> {
    val alias = alias("sign", id)
    if (!store.containsAlias(alias)) generateKeystoreEc(alias, KeyProperties.PURPOSE_SIGN)
    return keyResult(alias)
  }

  fun unwrapKey(id: String): Map<String, String> {
    val alias = alias("unwrap", id)
    if (Build.VERSION.SDK_INT >= 31) {
      if (!store.containsAlias(alias)) generateKeystoreEc(alias, KeyProperties.PURPOSE_AGREE_KEY)
      return keyResult(alias)
    }
    val pair = loadOrCreateWrappedPair(alias)
    return mapOf(
      "publicKey" to b64(point(pair.public as ECPublicKey)),
      "securityLevel" to if (isEmulator()) "development" else "os-protected",
    )
  }

  fun sign(id: String, payload: ByteArray): ByteArray {
    val alias = alias("sign", id)
    if (!store.containsAlias(alias)) signingKey(id)
    return Signature.getInstance("SHA256withECDSA").run {
      initSign(store.getKey(alias, null) as java.security.PrivateKey)
      update(payload)
      sign()
    }
  }

  fun sharedSecret(id: String, peer: ByteArray): ByteArray {
    val alias = alias("unwrap", id)
    val privateKey = if (Build.VERSION.SDK_INT >= 31) {
      if (!store.containsAlias(alias)) unwrapKey(id)
      store.getKey(alias, null) as java.security.PrivateKey
    } else loadOrCreateWrappedPair(alias).private
    val publicKey = KeyFactory.getInstance("EC").generatePublic(
      java.security.spec.X509EncodedKeySpec(spki(peer))
    )
    return KeyAgreement.getInstance("ECDH").run { init(privateKey); doPhase(publicKey, true); generateSecret() }
  }

  fun delete(id: String) {
    listOf(alias("sign", id), alias("unwrap", id)).forEach {
      if (store.containsAlias(it)) store.deleteEntry(it)
      if (store.containsAlias("$it.aes")) store.deleteEntry("$it.aes")
      prefs.edit().remove("$it.ct").remove("$it.iv").remove("$it.pub").apply()
    }
  }

  fun bestSecurityLevel() = signingKey("__capability_probe__")["securityLevel"]!!
  fun bestEcdhSecurityLevel() = unwrapKey("__capability_probe__")["securityLevel"]!!

  private fun generateKeystoreEc(alias: String, purposes: Int) {
    fun create(strongBox: Boolean) {
      val builder = KeyGenParameterSpec.Builder(alias, purposes)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
      if (Build.VERSION.SDK_INT >= 28) builder.setIsStrongBoxBacked(strongBox)
      KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
        initialize(builder.build()); generateKeyPair()
      }
    }
    if (Build.VERSION.SDK_INT >= 28) {
      try { create(true); return } catch (_: Exception) { }
    }
    create(false)
  }

  private fun keyResult(alias: String): Map<String, String> {
    val certificate = store.getCertificate(alias)
    return mapOf(
      "publicKey" to b64(point(certificate.publicKey as ECPublicKey)),
      "securityLevel" to securityLevel(alias),
    )
  }

  private fun securityLevel(alias: String): String = try {
    if (isEmulator()) return "development"
    val factory = KeyFactory.getInstance(store.getKey(alias, null).algorithm, "AndroidKeyStore")
    val info = factory.getKeySpec(store.getKey(alias, null), KeyInfo::class.java)
    if (Build.VERSION.SDK_INT >= 31) when (info.securityLevel) {
      KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
      KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
      else -> "os-protected"
    } else if (info.isInsideSecureHardware) "tee" else "os-protected"
  } catch (_: Exception) { "os-protected" }

  private fun loadOrCreateWrappedPair(alias: String): KeyPair {
    val ct = prefs.getString("$alias.ct", null)
    val iv = prefs.getString("$alias.iv", null)
    if (ct != null && iv != null) {
      val privateBytes = aesCipher(Cipher.DECRYPT_MODE, alias, unb64(iv)).doFinal(unb64(ct))
      val privateKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privateBytes))
      val publicBytes = prefs.getString("$alias.pub", null) ?: error("Missing wrapped public key")
      val publicKey = KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(unb64(publicBytes)))
      return KeyPair(publicKey, privateKey)
    }
    val pair = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
    val cipher = aesCipher(Cipher.ENCRYPT_MODE, alias, null)
    val encrypted = cipher.doFinal(pair.private.encoded)
    prefs.edit().putString("$alias.ct", b64(encrypted)).putString("$alias.iv", b64(cipher.iv))
      .putString("$alias.pub", b64(pair.public.encoded)).apply()
    return pair
  }

  private fun aesCipher(mode: Int, alias: String, iv: ByteArray?): Cipher {
    val aesAlias = "$alias.aes"
    if (!store.containsAlias(aesAlias)) {
      KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
        init(KeyGenParameterSpec.Builder(aesAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        generateKey()
      }
    }
    return Cipher.getInstance("AES/GCM/NoPadding").apply {
      if (mode == Cipher.ENCRYPT_MODE) init(mode, store.getKey(aesAlias, null) as SecretKey)
      else init(mode, store.getKey(aesAlias, null) as SecretKey, GCMParameterSpec(128, iv))
    }
  }

  private fun alias(kind: String, id: String) = "cavos.$kind.${digest(id)}"
}

private fun isEmulator(): Boolean =
  Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.contains("emulator") ||
    Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for")

private fun point(key: ECPublicKey): ByteArray = byteArrayOf(4) + fixed(key.w.affineX.toByteArray()) + fixed(key.w.affineY.toByteArray())
private fun fixed(value: ByteArray): ByteArray = if (value.size == 32) value else if (value.size > 32) value.copyOfRange(value.size - 32, value.size) else ByteArray(32 - value.size) + value
private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
private fun b64(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
private fun unb64(value: String) = Base64.decode(value, Base64.DEFAULT)
private fun b64url(value: ByteArray) = Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
private fun unb64url(value: String) = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

private fun spki(point: ByteArray): ByteArray {
  val prefix = byteArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00)
  return prefix + point
}

/** Minimal COSE scanner for ES256 x(-2) and y(-3) in attestation authData. */
private fun extractP256(bytes: ByteArray): ByteArray? {
  for (i in 0 until bytes.size - 70) if (bytes[i] == 0x21.toByte() && bytes[i+1] == 0x58.toByte() && bytes[i+2] == 0x20.toByte()) {
    for (j in i + 35 until minOf(bytes.size - 34, i + 80)) if (bytes[j] == 0x22.toByte() && bytes[j+1] == 0x58.toByte() && bytes[j+2] == 0x20.toByte()) {
      return byteArrayOf(4) + bytes.copyOfRange(i + 3, i + 35) + bytes.copyOfRange(j + 3, j + 35)
    }
  }
  return null
}

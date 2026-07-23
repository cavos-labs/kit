package xyz.cavos.kit

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import android.util.Base64

@RunWith(AndroidJUnit4::class)
class CavosKitInstrumentedTest {
  private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
  private val keys = NativeKeys(context.getSharedPreferences("cavos-kit-test", 0))

  @Test fun signingKeyPersistsSignsAndDeletes() {
    val id = "test-${System.nanoTime()}"
    val first = keys.signingKey(id)
    val second = keys.signingKey(id)
    assertArrayEquals(unb64(first.getValue("publicKey")), unb64(second.getValue("publicKey")))
    assertTrue(first.getValue("securityLevel") in setOf("strongbox", "tee", "os-protected", "development"))

    val message = "cavos-native-vector".toByteArray()
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki(unb64(first.getValue("publicKey"))))))
    verifier.update(message)
    assertTrue(verifier.verify(keys.sign(id, message)))

    keys.delete(id)
    assertNotEquals(first.getValue("publicKey"), keys.signingKey(id).getValue("publicKey"))
    keys.delete(id)
  }

  @Test fun ecdhMatchesPeer() {
    val id = "test-${System.nanoTime()}"
    val native = keys.unwrapKey(id)
    val peer = KeyPairGenerator.getInstance("EC").run {
      initialize(ECGenParameterSpec("secp256r1")); generateKeyPair()
    }
    val peerPoint = point(peer.public as java.security.interfaces.ECPublicKey)
    val nativeSecret = keys.sharedSecret(id, peerPoint)
    val nativePublic = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki(unb64(native.getValue("publicKey")))))
    val peerSecret = KeyAgreement.getInstance("ECDH").run {
      init(peer.private); doPhase(nativePublic, true); generateSecret()
    }
    assertArrayEquals(peerSecret, nativeSecret)
    keys.delete(id)
  }
}

private fun unb64(value: String) = Base64.decode(value, Base64.DEFAULT)
private fun point(key: java.security.interfaces.ECPublicKey): ByteArray =
  byteArrayOf(4) + fixed(key.w.affineX.toByteArray()) + fixed(key.w.affineY.toByteArray())
private fun fixed(value: ByteArray): ByteArray =
  if (value.size == 32) value else if (value.size > 32) value.copyOfRange(value.size - 32, value.size)
  else ByteArray(32 - value.size) + value
private fun spki(point: ByteArray): ByteArray = byteArrayOf(
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(),
  0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d,
  0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
) + point

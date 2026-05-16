import java.security.MessageDigest
import javax.crypto.Cipher
import java.security.KeyPairGenerator

class Vulnerable {
    fun badMD5(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(data)
    }

    fun badSHA1(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        return md.digest(data)
    }

    fun badDES(): Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")

    fun bad3DES(): Cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding")

    fun weakRSA(): KeyPairGenerator {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(1024)
        return kpg
    }

    fun disallowedDSA(): KeyPairGenerator =
        KeyPairGenerator.getInstance("DSA")
}

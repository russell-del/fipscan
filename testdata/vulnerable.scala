import java.security.MessageDigest
import javax.crypto.Cipher

object Vulnerable {
  def badMD5(data: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("MD5")
    md.digest(data)
  }

  def badSHA1(data: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-1")
    md.digest(data)
  }

  def badDES(): Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")

  def bad3DES(): Cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding")
}

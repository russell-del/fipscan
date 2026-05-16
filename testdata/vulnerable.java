import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Vulnerable {
    public byte[] badMD5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public byte[] badSHA1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public Cipher badDES() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public Cipher bad3DES() throws Exception {
        return Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }

    public Cipher badRC4() throws Exception {
        return Cipher.getInstance("RC4");
    }
}

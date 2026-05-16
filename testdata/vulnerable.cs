using System.Security.Cryptography;

public class Vulnerable
{
    public byte[] BadMD5(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    public byte[] BadSHA1(byte[] data)
    {
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(data);
    }
}

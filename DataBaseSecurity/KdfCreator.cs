using System.Security.Cryptography;

namespace DataBaseSecurity;

public class KdfCreator
{
    public byte[] DeriveKeyFromPassword(string password)
    {
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt: new byte[8], iterations: 10000, HashAlgorithmName.SHA256);
        return deriveBytes.GetBytes(32);
    }
}
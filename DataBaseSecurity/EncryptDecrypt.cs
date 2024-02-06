using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


namespace DataBaseSecurity;


public class EncryptDecrypt
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite([In] ref Credential userCredential, [In] uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(string targetName, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredFree(IntPtr buffer);

    

    internal void StoreKeyInCredentialManager(string keyName, string encryptedKey)
    {
        var encryptedKeyBytes = Encoding.Unicode.GetBytes(encryptedKey);

        var credential = new Credential
        {
            Type = CredentialType.Generic,
            TargetName = Marshal.StringToCoTaskMemUni(keyName),
            CredentialBlob = Marshal.AllocCoTaskMem(encryptedKeyBytes.Length),
            CredentialBlobSize = (uint)encryptedKeyBytes.Length,
            Persist = 1,
        };

        Marshal.Copy(encryptedKeyBytes, 0, credential.CredentialBlob, encryptedKeyBytes.Length);

        var success = CredWrite(ref credential, 0);
        if (!success)
        {
            Console.WriteLine($"Failed to store the key in Windows Credential Manager. Error code: {Marshal.GetLastWin32Error()}");
        }

        Marshal.FreeCoTaskMem(credential.TargetName);
        Marshal.FreeCoTaskMem(credential.CredentialBlob);
    }

    internal string? RetrieveKeyFromCredentialManager(string keyName)
    {
        var success = CredRead(keyName, CredentialType.Generic, 0, out var credentialPtr);

        if (success == false)
        {
            Console.WriteLine($"Failed to retrieve the key from Windows Credential Manager. Error code: {Marshal.GetLastWin32Error()}");
            return null;
        }

        var credential = Marshal.PtrToStructure<Credential>(credentialPtr);
        var encryptedKeyBytes = new byte[credential.CredentialBlobSize];
        Marshal.Copy(credential.CredentialBlob, encryptedKeyBytes, 0, (int)credential.CredentialBlobSize);
        var encryptedKey = Encoding.Unicode.GetString(encryptedKeyBytes);
        CredFree(credentialPtr);
        return encryptedKey;
    }

    public byte[] DeriveKeyFromPassword(string password)
    {
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt: new byte[8], iterations: 10000, HashAlgorithmName.SHA256);
        return deriveBytes.GetBytes(32);
    }

    internal string Encrypt(string plainText, byte[] key)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.GenerateIV();
        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
        byte[] encryptedBytes;

        using (var msEncrypt = new MemoryStream())
        {
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
            }
            encryptedBytes = msEncrypt.ToArray();
        }

        var result = new byte[aesAlg.IV.Length + encryptedBytes.Length];
        Buffer.BlockCopy(aesAlg.IV, 0, result, 0, aesAlg.IV.Length);
        Buffer.BlockCopy(encryptedBytes, 0, result, aesAlg.IV.Length, encryptedBytes.Length);

        return Convert.ToBase64String(result);
    }

    internal string Decrypt(string cipherText, byte[] key)
    {
        var cipherBytes = Convert.FromBase64String(cipherText);
        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.IV = cipherBytes.Take(16).ToArray();
        var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using var msDecrypt = new MemoryStream(cipherBytes, 16, cipherBytes.Length - 16);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }
}
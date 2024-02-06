using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


namespace DataBaseSecurity;


public class Decryptor
{

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(string targetName, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredFree(IntPtr buffer);

    internal string RetrieveKeyFromCredentialManager(string keyName)
    {
        var success = CredRead(keyName, CredentialType.Generic, 0, out var credentialPtr);

        if (success == false)
        {
            throw new InvalidOperationException($"Failed to retrieve the key from Windows Credential Manager. Error: {Marshal.GetLastWin32Error()}");
        }

        var credential = Marshal.PtrToStructure<Credential>(credentialPtr);
        var encryptedKeyBytes = new byte[credential.CredentialBlobSize];
        Marshal.Copy(credential.CredentialBlob, encryptedKeyBytes, 0, (int)credential.CredentialBlobSize);
        var encryptedKey = Encoding.Unicode.GetString(encryptedKeyBytes);
        CredFree(credentialPtr);
        return encryptedKey;
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
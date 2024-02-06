using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


namespace DataBaseSecurity;


public class Encryptor
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite([In] ref Credential userCredential, [In] uint flags);


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
}
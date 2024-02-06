namespace DataBaseSecurity;

public class InputController
{
    private EncryptDecrypt _encryptDecrypt;

    public InputController(EncryptDecrypt encryptDecrypt)
    {
        _encryptDecrypt = encryptDecrypt;
    }

    public void Get(string credManagerKey)
    {
        Console.Write("Enter your password: ");
        var userPassword = Console.ReadLine();
        var encryptionKey = _encryptDecrypt.DeriveKeyFromPassword(userPassword ?? throw new ArgumentNullException(userPassword));
        var encryptedDbPassword = _encryptDecrypt.RetrieveKeyFromCredentialManager(credManagerKey);
        var decryptedDbPassword = _encryptDecrypt.Decrypt(encryptedDbPassword ?? throw new ArgumentNullException(encryptedDbPassword), encryptionKey);
        Console.WriteLine($"Decrypted Database Password: {decryptedDbPassword}");
    }

    public void Set(string credManagerKey)
    {
        Console.Write("Enter your password: ");
        var userPassword = Console.ReadLine();
        var encryptionKey = _encryptDecrypt.DeriveKeyFromPassword(userPassword ?? throw new ArgumentNullException(userPassword));
        Console.Write("Enter your database password: ");
        var dbPassword = Console.ReadLine();
        var encryptedDbPassword = _encryptDecrypt.Encrypt(dbPassword ?? throw new ArgumentNullException(dbPassword), encryptionKey);
        _encryptDecrypt.StoreKeyInCredentialManager(credManagerKey, encryptedDbPassword);
    }
}
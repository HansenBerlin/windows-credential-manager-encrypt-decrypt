namespace DataBaseSecurity;

public class InputController
{
    private readonly Encryptor _encryptor;
    private readonly Decryptor _decryptor;
    private readonly KdfCreator _kdfCreator;
    private const string CredentialManagerKey = "SVO-DB-USER";
    private const string DefaultAdminUserName = "ADMIN";

    public InputController(Encryptor encryptor, Decryptor decryptor, KdfCreator kdfCreator)
    {
        _encryptor = encryptor;
        _kdfCreator = kdfCreator;
        _decryptor = decryptor;
    }

    public void PrintDbPassword()
    {
        Console.Write("Username: ");
        var userName = Console.ReadLine();
        Console.Write("Password: ");
        var userPassword = Console.ReadLine();
        if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(userPassword))
        {
            Console.WriteLine("Input cannot be empty");
            return;
        }
        var encryptionKey = _kdfCreator.DeriveKeyFromPassword(userPassword);
        var credManagerKey = CreateCredentialManagerKey(userName);
        var encryptedDbPassword = _decryptor.RetrieveKeyFromCredentialManager(credManagerKey);
        var decryptedDbPassword = _decryptor.Decrypt(encryptedDbPassword, encryptionKey);
        Console.WriteLine($"Decrypted Database Password: {decryptedDbPassword}");
    }

    public void InitialSetup()
    {
        Console.Write("Admin password: ");
        var adminPassword = Console.ReadLine();
        Console.Write("Enter your database password: ");
        var dbPassword = Console.ReadLine();
        if (string.IsNullOrEmpty(adminPassword) || string.IsNullOrEmpty(dbPassword))
        {
            Console.WriteLine("Password cannot be empty");
            return;
        }
        SaveInCredManagerFromMasterSecret(adminPassword, dbPassword);
        Console.WriteLine("Database password encrypted and saved successfully");
    }
    
    public void NewUserSetup()
    {
        Console.Write("Admin password: ");
        var adminPassword = Console.ReadLine();
        Console.Write("New user name: ");
        var userName = Console.ReadLine();
        Console.Write("New user password: ");
        var userPassword = Console.ReadLine();
        
        if (string.IsNullOrEmpty(adminPassword) || string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(userPassword))
        {
            Console.WriteLine("Input cannot be empty");
            return;
        }
        SaveInCredManagerForNewUser(userName, userPassword, adminPassword);
        Console.WriteLine("Database password for new user encrypted and saved successfully");
    }
    
    private void SaveInCredManagerFromMasterSecret(string adminUserPassword, string dbPassword)
    {
        var encryptionKey = _kdfCreator.DeriveKeyFromPassword(adminUserPassword);
        var encryptedDbPassword = _encryptor.Encrypt(dbPassword, encryptionKey);
        var credManagerKey = CreateCredentialManagerKey(DefaultAdminUserName);
        _encryptor.StoreKeyInCredentialManager(credManagerKey, encryptedDbPassword);
    }
    
    private void SaveInCredManagerForNewUser(string userName, string userPassword, string adminUserPassword)
    {
        var encryptionKeyAdmin = _kdfCreator.DeriveKeyFromPassword(adminUserPassword);
        var credManagerKeyAdmin = CreateCredentialManagerKey(DefaultAdminUserName);
        var encryptedDbPassword = _decryptor.RetrieveKeyFromCredentialManager(credManagerKeyAdmin);
        var decryptedDbPassword = _decryptor.Decrypt(encryptedDbPassword, encryptionKeyAdmin);
        
        var encryptionKeyUser = _kdfCreator.DeriveKeyFromPassword(userPassword);
        var encryptedDbPasswordUser = _encryptor.Encrypt(decryptedDbPassword, encryptionKeyUser);
        var credManagerKey = CreateCredentialManagerKey(userName);
        _encryptor.StoreKeyInCredentialManager(credManagerKey, encryptedDbPasswordUser);
    }
    
    private string CreateCredentialManagerKey(string userName)
    {
        return $"{CredentialManagerKey}-{userName.ToUpper()}";
    }
}
using System.Text;

namespace DataBaseSecurity;

public class InputController
{
    private readonly Encryptor _encryptor;
    private readonly Decryptor _decryptor;
    private readonly KdfCreator _kdfCreator;
    private const string CredentialManagerKey = "SOME-APP-DB-USER";
    private const string DefaultAdminUserName = "ADMIN";

    public InputController(Encryptor encryptor, Decryptor decryptor, KdfCreator kdfCreator)
    {
        _encryptor = encryptor;
        _kdfCreator = kdfCreator;
        _decryptor = decryptor;
    }

    private string PasswordInput()
    {
        var pw = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
           
            if ((int) key.Key >= 65 && (int) key.Key <= 90) 
            {
                pw.Append(key.KeyChar);
                Console.Write("*");
            }   
            else switch (key.Key)
            {
                case ConsoleKey.Backspace when pw.Length > 0:
                    pw.Remove(pw.Length - 1, 1);
                    Console.Write("\b \b");
                    break;
                case ConsoleKey.Enter when pw.Length >= 8:
                    return pw.ToString();
                case ConsoleKey.Enter:
                    pw.Clear();
                    Console.WriteLine("\nPassword must be at least 8 characters long. Retry!");
                    break;
            }
        }
        
        return pw.ToString();
    }

    public void PrintDbPassword()
    {
        Console.WriteLine("Enter username (leave empty for admin): ");
        var userName = Console.ReadLine();
        Console.WriteLine("Enter password: ");
        var userPassword = PasswordInput();
        userName = string.IsNullOrEmpty(userName) ? DefaultAdminUserName : userName;
        
        var encryptionKey = _kdfCreator.DeriveKeyFromPassword(userPassword);
        var credManagerKey = CreateCredentialManagerKey(userName);
        var encryptedDbPassword = _decryptor.RetrieveKeyFromCredentialManager(credManagerKey);
        var decryptedDbPassword = _decryptor.Decrypt(encryptedDbPassword, encryptionKey);
        Console.WriteLine($"\nDecrypted database password: {decryptedDbPassword}");
    }

    public void InitialSetup()
    {
        Console.WriteLine("Choose admin password: ");
        var adminPassword = PasswordInput();
        Console.WriteLine("\nEnter database password: ");
        var dbPassword = PasswordInput();
        
        SaveInCredManagerFromMasterSecret(adminPassword, dbPassword);
        Console.WriteLine("\nDatabase password encrypted and saved successfully");
    }
    
    public void NewUserSetup()
    {
        Console.WriteLine("Enter admin password: ");
        var adminPassword = PasswordInput();
        Console.WriteLine("\nChoose new users name: ");
        var userName = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(userName))
        {
            Console.WriteLine("Invalid user name");
            return;
        }
        Console.WriteLine("Choose new users password: ");
        var userPassword = PasswordInput();
        
        SaveInCredManagerForNewUser(userName, userPassword, adminPassword);
        Console.WriteLine("\nDatabase password for new user encrypted and saved successfully");
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
using DataBaseSecurity;

var inputContrller = new InputController(new Encryptor(),  new Decryptor(), new KdfCreator());
var inputSelection = 1;

Console.WriteLine("1. Initial Setup");
Console.WriteLine("2. New User Setup");
Console.WriteLine("3. Decrypt Database Password");
Console.WriteLine("4. Exit");

while (inputSelection <= 3)
{
    Console.Write("---------------------\nEnter your choice: ");
    var input = Console.ReadLine();
    Console.WriteLine("---------------------");
    if (int.TryParse(input, out inputSelection) == false)
    {
        Console.WriteLine("Invalid input");
        continue;
    }
    switch (inputSelection)
    {
        case 1:
            inputContrller.InitialSetup();
            break;
        case 2:
            inputContrller.NewUserSetup();
            break;
        case 3:
            inputContrller.PrintDbPassword();
            break;
        default:
            Console.WriteLine("Exiting");
            break;
    }
}
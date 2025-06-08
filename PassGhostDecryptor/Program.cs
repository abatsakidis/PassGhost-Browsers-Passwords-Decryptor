using System.Security.Cryptography;
using System.Text;

class Program
{
    static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
 ____                ____ _               _   
|  _ \ __ _ ___ ___ / ___| |__   ___  ___| |_ 
| |_) / _` / __/ __| |  _| '_ \ / _ \/ __| __|
|  __/ (_| \__ \__ \ |_| | | | | (_) \__ \ |_ 
|_|   \__,_|___/___/\____|_| |_|\___/|___/\__|
       PassGhost Decryptor - Unlock your vault
");
        Console.ResetColor();
    }

    static string DecryptString(string encryptedText, string password)
    {
        byte[] cipherBytes = Convert.FromBase64String(encryptedText);
        byte[] salt = Encoding.UTF8.GetBytes("s@1t!");
        var key = new Rfc2898DeriveBytes(password, salt, 10000);
        using var aes = Aes.Create();
        aes.Key = key.GetBytes(32);
        aes.IV = key.GetBytes(16);

        using var ms = new MemoryStream(cipherBytes);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);
        return sr.ReadToEnd();
    }

    static int Main(string[] args)
    {
        PrintBanner();

        if (args.Length < 1 || args.Contains("--help") || args.Contains("-h"))
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  PassGhostDecryptor <encrypted_file> [--key your_password]");
            return 1;
        }

        string filepath = args[0];
        if (!File.Exists(filepath))
        {
            Console.WriteLine("❌ File not found.");
            return 1;
        }

        string password = "secret_key"; // default key
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--key" && i + 1 < args.Length)
                password = args[i + 1];
        }

        try
        {
            string encrypted = File.ReadAllText(filepath);
            string decrypted = DecryptString(encrypted, password);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n✅ Decrypted content:\n");
            Console.ResetColor();
            Console.WriteLine(decrypted);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"❌ Failed to decrypt file: {ex.Message}");
            Console.ResetColor();
            return 1;
        }

        return 0;
    }
}

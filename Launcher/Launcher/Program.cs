using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;

namespace Launcher
{
    class Program
    {

        private static byte[] AesEncryptBlock(byte[] plainText, byte[] Key)
        {
            byte[] output_buffer = new byte[plainText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.ECB;

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;

                // Create a encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                encryptor.TransformBlock(plainText, 0, plainText.Length, output_buffer, 0);
            }

            return output_buffer;
        }

        // not used, but nice to have around
        private static byte[] AesDecryptBlock(byte[] cipherText, byte[] Key)
        {
            byte[] output_buffer = new byte[cipherText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.ECB;

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                decryptor.TransformBlock(cipherText, 0, cipherText.Length, output_buffer, 0);
            }
            return output_buffer;
        }

        static string GunBoundLoginParameters(string username, string password)
        {
            // final block (unknown) looks like 4 DWORDs, first one being always zero, second always nonzero, third and fourth are occasionally zero
            List<byte> result = new List<byte>();
            byte[] key = { 0xFA, 0xEE, 0x85, 0xF2, 0x40, 0x73, 0xD9, 0x16, 0x13, 0x90, 0x19, 0x7F, 0x6E, 0x56, 0x2A, 0x67 };
            byte[] finalBlock = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            result.AddRange(AesEncryptBlock(StringToBytes(username, 16), key));
            result.AddRange(AesEncryptBlock(StringToBytes(password, 16), key));
            result.AddRange(AesEncryptBlock(finalBlock, key));
            return BitConverter.ToString(result.ToArray()).Replace("-", "").ToUpper();
        }

        static byte[] StringToBytes(string inputString, int desiredLength)
        {
            List<byte> inputBytes = new List<byte>(Encoding.ASCII.GetBytes(inputString));
            int paddingBytesNeeded = desiredLength - inputBytes.Count;
            for (int i = 0; i < paddingBytesNeeded; i++)
            {
                inputBytes.Add(0);
            }
            return inputBytes.ToArray();
        }

        static Dictionary<string, string> ReadConfig(string appBasePath)
        {
            Dictionary<string, string> config = new Dictionary<string, string>();
            string configPath = appBasePath + "Launcher.ini";
            if (File.Exists(configPath))
            {
                Console.WriteLine("Config: Loading from Launcher.ini:");
                string[] configRows = File.ReadAllText(configPath).Trim().Replace("\r\n", "\n").Split('\n');
                foreach (string configRow in configRows)
                {
                    string[] configKeyValue = configRow.Split('=');
                    if (configKeyValue.Length < 2)
                    {
                        continue;
                    }
                    string configKey = configKeyValue[0].Trim().ToUpper();
                    string configValue = configKeyValue[1];
                    config.Add(configKey, configValue);
                    Console.WriteLine(string.Format("Config: Loading key '{0}' with value '{1}'", configKey, configValue));
                }
            }
            return config;
        }

        static void LaunchGunbound(string binaryPath, string credentialsEncrypted, bool createSuspended, string dllToInject = "")
        {
            int pid = NativeAPI.CreateProcessWrapper(binaryPath, credentialsEncrypted, createSuspended);
            if (dllToInject.Length != 0)
            {
                NativeAPI.InjectDLL(pid, dllToInject);
                Console.WriteLine("Injected DLL: " + dllToInject);
            }

            if (createSuspended)
            {
                Console.WriteLine("Press any key to resume process");
                Console.ReadKey();
                NativeAPI.ResumeProcess(pid);
            }
        }

        static RegistryKey RestoreBaseRegistry()
        {
            RegistryKey gbKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            gbKey.CreateSubKey(@"Software\Softnyx\GunBound");
            // writing to the RegistryKey from CreateSubKey fails, so the key is reopened below with write access
            gbKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            gbKey = gbKey.OpenSubKey(@"Software\Softnyx\GunBound", true);

            gbKey.SetValue("AppID1", 1, RegistryValueKind.DWord);
            gbKey.SetValue("AppID2", 2, RegistryValueKind.DWord);
            gbKey.SetValue("AppID3", 3, RegistryValueKind.DWord);
            gbKey.SetValue("AutoRefresh", 1, RegistryValueKind.DWord);
            gbKey.SetValue("Background", new byte[] { 0x01}, RegistryValueKind.Binary);
            gbKey.SetValue("BuddyIP", "127.0.0.1", RegistryValueKind.String);
            gbKey.SetValue("ChannelName", new byte[] { 0x00 }, RegistryValueKind.Binary);
            gbKey.SetValue("Effect3D", new byte[] { 0x02 }, RegistryValueKind.Binary);
            gbKey.SetValue("EffectVolume", 95, RegistryValueKind.DWord);
            gbKey.SetValue("GameName", new byte[] { 0x00 }, RegistryValueKind.Binary);
            gbKey.SetValue("IP", "127.0.0.1", RegistryValueKind.String);
            gbKey.SetValue("Language", 0, RegistryValueKind.DWord);
            gbKey.SetValue("LastID", new byte[] { 0x00 }, RegistryValueKind.Binary);
            gbKey.SetValue("LastServer", -1, RegistryValueKind.DWord);
            gbKey.SetValue("Location", @"C:\Program Files (x86)\softnyx\GunBound\", RegistryValueKind.String);
            gbKey.SetValue("MidiMode", new byte[] { 0x01 }, RegistryValueKind.Binary);
            gbKey.SetValue("MouseSpeed", 50, RegistryValueKind.DWord);
            gbKey.SetValue("MusicVolume", 95, RegistryValueKind.DWord);
            gbKey.SetValue("port", 8372, RegistryValueKind.DWord);
            gbKey.SetValue("Screen", @"C:\Program Files (x86)\softnyx\GunBound\Screen\", RegistryValueKind.String); // GKS
            gbKey.SetValue("ShootingMode", new byte[] { 0x00 }, RegistryValueKind.Binary);
            gbKey.SetValue("Url_Fetch", "http://fetch.gunbound.co.kr/fetch/fetch.dll", RegistryValueKind.String);
            gbKey.SetValue("Url_ForgotPwd", "http://fetch.gunbound.co.kr/fetch/pwdlost/", RegistryValueKind.String);
            gbKey.SetValue("Url_Notice", "http://www.gunbound.co.kr/fetch_note/note.htm", RegistryValueKind.String);
            gbKey.SetValue("Url_Signup", "http://fetch.gunbound.co.kr/fetch/signup/", RegistryValueKind.String);
            gbKey.SetValue("Version", 313, RegistryValueKind.DWord);

            return gbKey;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("GunBound Launcher");
            Console.Write("Available options: ");

            string credentialsUsername = "";
            string credentialsPassword = "";
            string credentialsEncrypted = "";

            string[] CONFIG_KEYS = { "CREATE_SUSPENDED", "EXIT_IMMEDIATELY", "INJECT_DLL", "USERNAME", "PASSWORD", "SERVER", "VERSION" };
            foreach (string configAvailableKey in CONFIG_KEYS)
            {
                Console.Write(string.Format("'{0}' ", configAvailableKey));
            }
            Console.WriteLine();

            // Print and load args
            Console.WriteLine("Launch parameters:");
            foreach (string arg in args)
            {
                Console.Write(string.Format("'{0}' ", arg));
            }
            Console.WriteLine();
            if (args.Length == 2)
            {
                credentialsUsername = args[0];
                credentialsPassword = args[1];
                credentialsEncrypted = GunBoundLoginParameters(credentialsUsername, credentialsPassword);
                Console.WriteLine("Loaded credentials from process parameters");
            }


            string appBasePath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\";

            // parse Launcher.ini
            Dictionary<string, string> config = ReadConfig(appBasePath);
            if (config.Count == 0)
            {
                Console.WriteLine("Config file could not be read. Please check if a valid Launcher.ini exists in the same folder");
                Console.ReadKey();
                return;
            }
            
            RegistryKey gbKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            gbKey = gbKey.OpenSubKey(@"Software\Softnyx\GunBound", true);
            if (gbKey == null)
            {
                Console.WriteLine("Registry: Base registry not created, restoring..");
                gbKey = RestoreBaseRegistry();
            }

            // set GunBound's base path to our directory
            Console.WriteLine("Registry: Writing Location and Screen");
            gbKey.SetValue("Location", appBasePath, RegistryValueKind.String);
            gbKey.SetValue("Screen", appBasePath + "Screen\\", RegistryValueKind.String);

            if (config.ContainsKey("VERSION"))
            {
                Console.WriteLine("Registry: Writing version");
                gbKey.SetValue("Version", int.Parse(config["VERSION"]), RegistryValueKind.DWord);
            }
            if (config.ContainsKey("SERVER"))
            {
                Console.WriteLine("Registry: Writing IP and BuddyIP");
                gbKey.SetValue("IP", config["SERVER"], RegistryValueKind.String);
                gbKey.SetValue("BuddyIP", config["SERVER"], RegistryValueKind.String);
            }

            if (credentialsUsername.Length == 0)
            {
                if (config.ContainsKey("USERNAME") && config.ContainsKey("PASSWORD"))
                {
                    credentialsUsername = config["USERNAME"];
                    credentialsPassword= config["PASSWORD"];
                    credentialsEncrypted = GunBoundLoginParameters(credentialsUsername, credentialsPassword);
                }
                else
                {
                    Console.WriteLine("Please check if username and password are set in either the process parameter or config file.");
                }
            }

            if (credentialsEncrypted.Length != 0)
            {
                Console.WriteLine("Attempting to start GunBound.gme with credentials: " + credentialsEncrypted);
                string binaryPath = appBasePath + "GunBound.gme";
                if (File.Exists(binaryPath))
                {
                    bool createSuspended = true;
                    if (config["CREATE_SUSPENDED"].Trim().ToUpper() == "FALSE")
                    {
                        createSuspended = false;
                    }
                    string dllToInject = "";
                    if (config.ContainsKey("INJECT_DLL"))
                    {
                        dllToInject = appBasePath + config["INJECT_DLL"];
                        if (!File.Exists(dllToInject))
                        {
                            dllToInject = "";
                            Console.WriteLine("INJECT_DLL was requested, but the requested file does not exist");
                        }
                    }
                    
                    LaunchGunbound(binaryPath, credentialsEncrypted, createSuspended, dllToInject);
                }
                else
                {
                    Console.WriteLine("Could not find the client executable. Please run me in the same folder as the GunBound.gme file");
                }

            }
            
            if (config.ContainsKey("EXIT_IMMEDIATELY"))
            {
                if (config["EXIT_IMMEDIATELY"].Trim().ToUpper() == "FALSE")
                {
                    Console.WriteLine("Press any key to exit");
                    Console.ReadKey();
                }
            }
        }
    }
}

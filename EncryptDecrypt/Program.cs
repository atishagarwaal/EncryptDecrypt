using System.Security.Cryptography;
using System.Text;

public class EncryptionHelper
{
    private static string key = "7yde62dve92hdte7210khst72thw84fs";

    public static string EncryptString(string plainText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.GenerateIV(); // Generate a random IV

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                // Prepend IV to ciphertext
                memoryStream.Write(aes.IV, 0, aes.IV.Length);

                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                }

                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }
    }

    public static string DecryptString(string cipherText)
    {
        byte[] buffer = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);

            // Extract IV from the beginning of the ciphertext
            byte[] iv = new byte[16];
            Array.Copy(buffer, 0, iv, 0, iv.Length);
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream(buffer, iv.Length, buffer.Length - iv.Length))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader(cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }
}

class Program
{
    static void Main()
    {
        string original = "Hello, world!";

        string encrypted = EncryptionHelper.EncryptString(original);
        Console.WriteLine("Encrypted: " + encrypted);

        string decrypted = EncryptionHelper.DecryptString(encrypted);
        Console.WriteLine("Decrypted: " + decrypted);
    }
}

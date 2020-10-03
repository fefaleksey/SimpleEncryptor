using System;

namespace SimpleEncryptor
{

    internal class Program
    {
        public static void Main(string[] args)
        {
            var encrypted = Crypter.Encrypt("some text to encrypt", "qwerty", out var key, true);
            var decrypted = Crypter.Decrypt(encrypted, key);
            Console.WriteLine($"Decrypted text: \"{decrypted}\"");
        }
    }
}
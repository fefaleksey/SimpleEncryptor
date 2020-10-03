using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Replicon.Cryptography.SCrypt;

namespace SimpleEncryptor
{
    public static class Crypter
    {
        /// <summary>
        /// Encrypts a message with a specified password using the AES-256-CBC algorithm
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="password">Password to encrypt</param>
        /// <param name="generatedCryptKey">Out. A crypt key for encoding and decoding</param>
        /// <param name="logDebugInfo">If true, debug logs will be printed</param>
        /// <returns>Encrypted message</returns>
        public static byte[] Encrypt(string message, string password, out byte[] generatedCryptKey, bool logDebugInfo = false)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message", "encryptedMessage can not be null");
            }

            if (password == null)
            {
                throw new ArgumentNullException("password", "encryptedMessage can not be null");
            }

            // 1. Get key
            var key = GenerateKey(password);

            // 2. Separate key
            var cryptKey = key.Take(key.Length / 2).ToArray();
            generatedCryptKey = cryptKey;
            var hmacKey = key.Skip(key.Length / 2).ToArray();

            // 3. Padding text (using PKSC7 algorithm, 16 bytes border)
            var messageBytes = Encoding.Unicode.GetBytes(message);
            var messageBytesPadded = AddPkcs7Padding(messageBytes);

            // 4. Encrypt padded text using AES-256-CBC
            var encrypted = EncryptAes(Encoding.Unicode.GetString(messageBytesPadded), cryptKey);

            if (logDebugInfo)
            {
                Console.WriteLine($"Encrypted bytes: {BitConverter.ToString(encrypted)}");
                Console.WriteLine($"Length: {encrypted.Length}");
            }

            // 5. Calculate MAC using HMAC-SHA256
            if (logDebugInfo)
            {
                HMACSHA256 hmac = new HMACSHA256(hmacKey);
                var mac = hmac.ComputeHash(encrypted);
                Console.WriteLine($"MAC: {BitConverter.ToString(mac)}");
            }

            return encrypted;
        }

        /// <summary>
        /// Decrypts a message with a specified cryptKey using the AES-256-CBC algorithm
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message for decrypt</param>
        /// <param name="cryptKey">Secret crypt key</param>
        /// <returns>Decrypted message</returns>
        public static string Decrypt(byte[] encryptedMessage, byte[] cryptKey)
        {
            if (encryptedMessage == null)
            {
                throw new ArgumentNullException("encryptedMessage", "encryptedMessage can not be null");
            }

            if (cryptKey == null)
            {
                throw new ArgumentNullException("cryptKey", "cryptKey cannot be null");
            }

            if (cryptKey.Length != 32)
            {
                throw new ArgumentException("Invalid length of cryptKey. Length must be 32.", "cryptKey");
            }

            string result;
            try
            {
                string decryptedString = DecryptAes(encryptedMessage, cryptKey);
                var decryptedBytes = Encoding.Unicode.GetBytes(decryptedString);
                var decryptedBytesUnpadded = RemovePkcs7Padding(decryptedBytes);

                result = Encoding.Unicode.GetString(decryptedBytesUnpadded);
            }
            catch (Exception)
            {
                throw new ArgumentException("Cannot decrypt message. Probably cryptKey is not valid");
            }

            return result;
        }

        private static byte[] GenerateKey(string password)
        {
            const ulong n = 16384;
            const uint r = 16, p = 1;

            var salt = SCrypt.GenerateSalt(saltLengthBytes: 16u, n, r, p, hashLengthBytes: 128u);
            SCrypt.ParseSalt(salt, out var saltBytes, out _, out _, out _, out var hashLengthBytes);
            var passwordBytes = Encoding.Unicode.GetBytes(password);
            var key = SCrypt.DeriveKey(passwordBytes, saltBytes, n, r, p, 64u);

            return key;
        }

        private static T[] SubArray<T>(T[] arr, int start, int length)
        {
            var result = new T[length];
            Buffer.BlockCopy(arr, start, result, 0, length);

            return result;
        }

        private static byte[] AddPkcs7Padding(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data", "data can not be null");
            }
            const int paddingBorder = 16;
            int paddingLength = paddingBorder - data.Length % paddingBorder;

            var output = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, output, 0, data.Length);
            for (var i = data.Length; i < output.Length; i++)
            {
                output[i] = (byte)paddingLength;
            }

            return output;
        }

        private static byte[] RemovePkcs7Padding(byte[] paddedByteArray)
        {
            if (paddedByteArray == null)
            {
                throw new ArgumentNullException("paddedByteArray", "paddedByteArray can not be null");
            }

            var last = paddedByteArray[paddedByteArray.Length - 1];

            if (paddedByteArray.Length < last)
            {
                // there is nothing to unpad
                return paddedByteArray;
            }

            for (int i = paddedByteArray.Length - 2; i >= paddedByteArray.Length - last; i--)
            {
                if (paddedByteArray[i] != last)
                {
                    // there is nothing to unpad
                    return paddedByteArray;
                }
            }

            return SubArray(paddedByteArray, 0, paddedByteArray.Length - last);
        }

        private static byte[] EncryptAes(string paddedData, byte[] key)
        {
            byte[] encrypted;
            byte[] iv;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

                aesAlg.GenerateIV();
                iv = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(paddedData);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[iv.Length + encrypted.Length];
            Array.Copy(iv, 0, combinedIvCt, 0, iv.Length);
            Array.Copy(encrypted, 0, combinedIvCt, iv.Length, encrypted.Length);

            // Return the encrypted bytes from the memory stream.
            return combinedIvCt;

        }

        private static string DecryptAes(byte[] cipherTextCombined, byte[] key)
        {

            // Declare the string used to hold the decrypted text.
            string plaintext = null;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}

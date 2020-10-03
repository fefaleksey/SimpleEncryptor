using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleEncryptor;

namespace TestTask.Tests
{
    [TestClass]
    public class EncryptingTests
    {
        [TestMethod]
        public void EmptyMessageTest()
        {
            string message = "";
            var encryptedBytes = Crypter.Encrypt(message, "password", out var cryptKey);
            var decryptedMessage = Crypter.Decrypt(encryptedBytes, cryptKey);

            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public void IncorrectKeyTest()
        {
            string message = "";
            var encryptedBytes = Crypter.Encrypt(message, "password", out var cryptKey);

            if (cryptKey[0] != 0xAA)
            {
                cryptKey[0] = 0xAA;
            }
            else
            {
                cryptKey[0] = 0x00;
            }

            Assert.ThrowsException<ArgumentException>(() => Crypter.Decrypt(encryptedBytes, cryptKey));
        }

        [TestMethod]
        public void NormalMessageTest()
        {
            string message = "MAT-MEX lutshe vseh";
            var encryptedBytes = Crypter.Encrypt(message, "password", out var cryptKey);
            var decryptedMessage = Crypter.Decrypt(encryptedBytes, cryptKey);

            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public void LongMessageTest()
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("Ya s MAT-MEXa, pomogite ");
            for (var i = 0; i < 10000; i++)
            {
                stringBuilder.AppendLine("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            }
            var message = stringBuilder.ToString();
            var encryptedBytes = Crypter.Encrypt(message, "password", out var cryptKey);
            var decryptedMessage = Crypter.Decrypt(encryptedBytes, cryptKey);

            Assert.AreEqual(message, decryptedMessage);
        }
    }
}

using System.Security.Cryptography;
using System.Text;

namespace PublicAndPrivateKeys;

internal class Program
{
    static void Main(string[] args)
    {
        using (var rsa = new RSACryptoServiceProvider(2048)) 
        {
            rsa.PersistKeyInCsp = false;

            string publicKey = rsa.ToXmlString(false);
            string privateKey = rsa.ToXmlString(true);


            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Public key (available for every one):\n" + publicKey);



            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\n\nPrivate key (available on for me):\n" + privateKey);         


            //User 1 wants to send me a meessage using my public key:
            string messageFromUser1 = "Hello from User 1!";
            string encryptedMessage = Encrypt(messageFromUser1, publicKey); 
            Console.ForegroundColor= ConsoleColor.DarkYellow;
            Console.WriteLine("\n\nUser 1 send an encrypted message:\n" + encryptedMessage);

            //I want to decrypt it using my private key
            Console.ForegroundColor= ConsoleColor.Green;
            string decryptedMessage = Decrypt(encryptedMessage, privateKey);
            Console.WriteLine("\n\nI decrypted the message:\n" + decryptedMessage);


            //I want to sign a message for User 2
            string signature = Sign(decryptedMessage, privateKey);
            Console.ForegroundColor= ConsoleColor.DarkBlue;
            Console.WriteLine("\n\nMy digital sign:\n" + signature);

            //User 2 wants to verify my signature
            bool isSignatureValid = Verify(decryptedMessage, signature.Replace('a','c'), publicKey);
            Console.ForegroundColor= ConsoleColor.DarkCyan;
            Console.WriteLine("\n\nUser2 checks my signature...\n" + (isSignatureValid ? "Signature is valid" : "Signature is INVALID"));
            Console.ResetColor();


        }

        #region Encryption | Decription

        static string Encrypt(string data, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicKey);
                var encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(data), false);
                return Convert.ToBase64String(encryptedBytes);
            }
        }

        static string Decrypt(string encryptedData, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(privateKey);
                var decryptedBytes = rsa.Decrypt(Convert.FromBase64String(encryptedData),false);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

        #endregion

        #region Digital Sign

        static string Sign(string data, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(privateKey);
                var dataBytes = Encoding.UTF8.GetBytes(data);
                var signatureBytes = rsa.SignData(dataBytes, CryptoConfig.MapNameToOID("SHA256")!);
                return Convert.ToBase64String(signatureBytes);
            }
        }


        static bool Verify(string data, string signature, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicKey);
                var dataBytes = Encoding.UTF8.GetBytes(data);
                var signatureBytes = Convert.FromBase64String(signature);
                return rsa.VerifyData(dataBytes, CryptoConfig.MapNameToOID("SHA256")!, signatureBytes);
            }
        }

        #endregion


    }
}

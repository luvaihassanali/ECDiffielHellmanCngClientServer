using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    class Client
    {
        public static void Main(string[] args)
        {
            GetSecretMessageFromServer();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static void GetSecretMessageFromServer()
        {
            using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng())
            {
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] clientPublicKey = ecdh.PublicKey.ToByteArray();
                string clientPublicKeyBase64 = Convert.ToBase64String(clientPublicKey);
                string clientId = Guid.NewGuid().ToString(); // Generate a unique client ID
                Console.WriteLine($"CLIENT-{clientId} public key: " + clientPublicKeyBase64); // Updated log output

                // Step 1: Send CLIENT [ID: <id>] public key to SERVER via POST request and receive SERVER public key
                string serverResponse = SendPost("http://localhost:8000/ecdhSession/", clientPublicKeyBase64, clientId);
                string[] responseParts = serverResponse.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string serverPublicKeyBase64 = responseParts[0]; // SERVER public key
                string nonce = responseParts[1]; // Nonce
                Console.WriteLine($"CLIENT-{clientId} public key sent to SERVER. SERVER public key received: " + serverPublicKeyBase64);

                // Parse SERVER public key
                byte[] serverPublicKey = Convert.FromBase64String(serverPublicKeyBase64);
                CngKey serverKey = CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] clientKey = ecdh.DeriveKeyMaterial(serverKey);

                // Step 2: Send the trigger message with nonce
                string response = SendPost($"http://localhost:8000/ecdhSession/", $"Trigger message exchange {nonce}", clientId);
                Console.WriteLine($"Received response from SERVER for CLIENT-{clientId}: " + response);

                string[] parts = response.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2)
                {
                    try
                    {
                        byte[] encryptedMessage = Convert.FromBase64String(parts[0]);
                        byte[] iv = Convert.FromBase64String(parts[1]);

                        // Decrypt and display the message
                        Receive(clientKey, encryptedMessage, iv);
                    }
                    catch (FormatException ex)
                    {
                        Console.WriteLine($"Error decoding the encrypted message or IV for CLIENT-{clientId}: " + ex.Message);
                    }
                }
                else
                {
                    Console.WriteLine($"CLIENT-{clientId} received unexpected response format.");
                }
            }
        }

        private static string SendPost(string url, string data, string clientId)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers.Add("Client-ID", clientId); // Add Client-ID to headers
            request.ContentLength = dataBytes.Length;

            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(dataBytes, 0, dataBytes.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }

        private static void Receive(byte[] key, byte[] encryptedMessage, byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();
                        string message = Encoding.UTF8.GetString(plaintext.ToArray());
                        Console.WriteLine($"Decrypted Message from SEVER: " + message);
                    }
                }
            }
        }
    }
}
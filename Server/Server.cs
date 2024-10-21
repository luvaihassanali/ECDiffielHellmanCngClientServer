using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class Server
    {
        private static readonly HttpListener listener = new HttpListener();
        private static readonly ConcurrentDictionary<string, (byte[] Key, DateTime Expiration)> clientSessionKeys = new ConcurrentDictionary<string, (byte[], DateTime)>();
        private static readonly ConcurrentDictionary<string, (string Nonce, DateTime Expiration)> nonces = new ConcurrentDictionary<string, (string, DateTime)>();
        private static readonly TimeSpan NonceExpirationTime = TimeSpan.FromMinutes(5); // Nonce expiration time

        public static void Main(string[] args)
        {
            listener.Prefixes.Add("http://localhost:8000/ecdhSession/");
            listener.Start();
            Console.WriteLine("SERVER is waiting for clients to connect...");

            // Start a background task to clean up expired sessions and nonces
            Task.Run(CleanUpExpiredSessions);  // Optional

            while (true)
            {
                HttpListenerContext context = listener.GetContext(); // Wait for a connection
                Task.Run(() => HandleRequest(context)); // Handle the request asynchronously
            }

            //listener.Stop();
        }

        private static async Task HandleRequest(HttpListenerContext context)
        {
            HttpListenerRequest request = context.Request;
            HttpListenerResponse response = context.Response;

            string clientId = request.Headers["Client-ID"]; // Assume each client sends a unique ID in the headers

            using (StreamReader reader = new StreamReader(request.InputStream, Encoding.UTF8))
            {
                string requestData = await reader.ReadToEndAsync();
                string[] parts = requestData.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                Console.WriteLine($"Received data from CLIENT-{clientId}: {requestData}");

                // Step 1: Key Exchange
                if (parts.Length == 1)
                {
                    await HandleKeyExchange(parts[0], clientId, response);
                }
                // Step 2: Trigger message exchange
                else if (parts.Length == 4 && parts[0] == "Trigger" && parts[1] == "message" && parts[2] == "exchange")
                {
                    await HandleMessageExchange(parts[3], clientId, response);

                }
                else
                {
                    Console.WriteLine($"Unexpected request format from CLIENT-{clientId}."); // Updated log output
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                }
            }

            response.Close();
        }

        private static async Task HandleKeyExchange(string clientPublicKeyBase64, string clientId, HttpListenerResponse response)
        {
            try
            {
                // Decode client's public key
                byte[] clientPublicKey = Convert.FromBase64String(clientPublicKeyBase64);
                using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng())
                {
                    ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    ecdh.HashAlgorithm = CngAlgorithm.Sha256;

                    // Derive the session key
                    CngKey clientSessionKey = CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob);
                    byte[] serverSessionKey = ecdh.DeriveKeyMaterial(clientSessionKey);

                    // Store the session key with expiration time
                    clientSessionKeys[clientId] = (serverSessionKey, DateTime.UtcNow.AddMinutes(5)); // 5 minutes expiration

                    // Generate a unique nonce for this client session
                    string nonce = Guid.NewGuid().ToString();
                    nonces[clientId] = (nonce, DateTime.UtcNow.Add(NonceExpirationTime)); // Expire in 5 minutes

                    // Send SERVER public key and nonce as the response
                    byte[] serverPublicKey = ecdh.PublicKey.ToByteArray();
                    string serverPublicKeyBase64 = Convert.ToBase64String(serverPublicKey);
                    string responseMessage = $"{serverPublicKeyBase64} {nonce}";

                    byte[] buffer = Encoding.UTF8.GetBytes(responseMessage);
                    await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    Console.WriteLine($"SERVER public key and nonce sent to CLIENT-{clientId}: " + responseMessage);
                }
            }
            catch (FormatException ex)
            {
                Console.WriteLine($"Error decoding CLIENT-{clientId} public key: " + ex.Message);
                response.StatusCode = (int)HttpStatusCode.BadRequest;
            }
        }

        private static async Task HandleMessageExchange(string receivedNonce, string clientId, HttpListenerResponse response)
        {
            if (clientSessionKeys.TryGetValue(clientId, out (byte[] Key, DateTime Expiration) session) &&
                nonces.TryRemove(clientId, out (string Nonce, DateTime Expiration) nonce) && nonce.Nonce == receivedNonce)
            {
                // Validate nonce expiration
                if (nonce.Expiration < DateTime.UtcNow)
                {
                    Console.WriteLine($"CLIENT-{clientId} nonce expired.");
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    return;
                }

                try
                {
                    // Prepare to send the encrypted message back to the client
                    byte[] encryptedMessage;
                    byte[] iv;
                    Send(session.Key, $"Secret message token {Guid.NewGuid()}", out encryptedMessage, out iv);

                    // Respond with encrypted message and IV
                    string encryptedMessageBase64 = Convert.ToBase64String(encryptedMessage);
                    string ivBase64 = Convert.ToBase64String(iv);
                    string responseMessage = $"{encryptedMessageBase64}\n{ivBase64}";

                    byte[] responseBuffer = Encoding.UTF8.GetBytes(responseMessage);
                    await response.OutputStream.WriteAsync(responseBuffer, 0, responseBuffer.Length);
                    Console.WriteLine($"Encrypted message and IV sent to CLIENT-{clientId}."); // Updated log output
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during message exchange with CLIENT-{clientId}: " + ex.Message);
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                }
            }
            else
            {
                Console.WriteLine($"Invalid nonce or session key not found for CLIENT-{clientId}.");
                response.StatusCode = (int)HttpStatusCode.BadRequest;
            }
        }

        private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;

                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }
            }
        }

        private static async Task CleanUpExpiredSessions()
        {
            while (true)
            {
                // Remove expired session keys
                List<string> expiredKeys = clientSessionKeys.Where(kvp => kvp.Value.Expiration < DateTime.UtcNow).Select(kvp => kvp.Key).ToList();
                foreach (string key in expiredKeys)
                {
                    clientSessionKeys.TryRemove(key, out _);
                    Console.WriteLine($"Removed expired session for CLIENT-{key}.");
                }

                // Remove expired nonces
                List<string> expiredNonces = nonces.Where(n => n.Value.Expiration < DateTime.UtcNow).Select(n => n.Key).ToList();
                foreach (string key in expiredNonces)
                {
                    nonces.TryRemove(key, out _);
                    Console.WriteLine($"Removed expired nonce for CLIENT-{key}.");
                }

                // Run the cleanup every minute
                await Task.Delay(TimeSpan.FromMinutes(1));
            }
        }
    }
}

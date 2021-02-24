using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EstClient
{
    class Program
    {
        const string caEndpoint = "https://est-server:8443/.well-known/est/cacerts";
        const string simpleEnrollEndpoint = "https://est-server:8443/.well-known/est/simpleenroll";

        static async Task Main(string[] args)
        {
            await GetEstCaCertificate();
            await SimpleEnrollWithCSR();
        }

        static async Task SimpleEnrollWithCSR()
        {
            var csr = GenerateCSR();
            var cert = await MakePostHttpCall(simpleEnrollEndpoint, csr, AcceptServerCertificate);
        }

        private static string GenerateCSR()
        {
            string subjectName =
               "CN=www.companyName.com,O=Company Name,OU=Department,T=Area,ST=State,C=Country";

            RSACryptoServiceProvider cryptoServiceProvider =
               new RSACryptoServiceProvider(4096);

            CertificateRequest certificateRequest =
               new CertificateRequest(subjectName,
                  cryptoServiceProvider, HashAlgorithmName.SHA256,
                  RSASignaturePadding.Pkcs1);

            return DERtoPEM(
                  certificateRequest.CreateSigningRequest(
                     X509SignatureGenerator.CreateForRSA(
                        cryptoServiceProvider,
                        RSASignaturePadding.Pkcs1)));
        }

        private static string DERtoPEM(byte[] bytesDER)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");

            string base64 = Convert.ToBase64String(bytesDER);

            int offset = 0;
            const int LineLength = 64;
            while (offset < base64.Length)
            {
                int lineEnd = Math.Min(offset + LineLength, base64.Length);
                builder.AppendLine(
                   base64.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            builder.AppendLine("-----END CERTIFICATE REQUEST-----");
            return builder.ToString();
        }

        static async Task GetEstCaCertificate()
        {
            var caCertP7 = await MakeGetHttpCall(caEndpoint, AcceptServerCertificate);

            // Parse
            byte[] decodedContent = Convert.FromBase64String(caCertP7);
            SignedCms certContainer = new SignedCms();
            certContainer.Decode(decodedContent);

            foreach (var certificate in certContainer.Certificates)
            {
                Console.WriteLine($"CERT INFOS.....");
                Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
                Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
                Console.WriteLine($"Issuer: {certificate.Issuer}");
                Console.WriteLine($"Subject: {certificate.Subject}");
            }
        }

        private static async Task<string> MakeGetHttpCall(string endpoint, Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> serverCertValidationCallBack)
        {
            // Create an HttpClientHandler object and set to use default credentials
            using (HttpClientHandler handler = new HttpClientHandler())
            {
                // Set custom server validation callback
                handler.ServerCertificateCustomValidationCallback = serverCertValidationCallBack;
                // Create an HttpClient object
                using (HttpClient client = new HttpClient(handler))
                {
                    try
                    {
                        var stringTask = client.GetStringAsync(endpoint);
                        var responseStringRaw = await stringTask;
                        Console.WriteLine($"Content size: {responseStringRaw.Length}");
                        Console.Write($"Content: {responseStringRaw}");
                        
                        return responseStringRaw;
                    }
                    catch
                    {
                        throw;
                    }
                }
            }
        }

        private static async Task<string> MakePostHttpCall(string endpoint, string data, Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> serverCertValidationCallBack)
        {
            // Create an HttpClientHandler object and set to use default credentials
            using (HttpClientHandler handler = new HttpClientHandler())
            {
                // Set custom server validation callback
                handler.ServerCertificateCustomValidationCallback = serverCertValidationCallBack;
                // Create an HttpClient object
                using (HttpClient client = new HttpClient(handler))
                {
                    try
                    {
                        // Add a new Request Message
                        HttpRequestMessage requestMessage = new HttpRequestMessage(HttpMethod.Post, endpoint);

                        // Add our custom headers
                        requestMessage.Headers.Add("Content-Type", "application/pkcs10");

                        // Add Body
                        requestMessage.Content = new ByteArrayContent(UTF8Encoding.UTF8.GetBytes(data));

                        var stringTask = client.SendAsync(requestMessage);
                        var response = await stringTask;
                        var responseString = await response.Content.ReadAsStringAsync();
                        Console.WriteLine($"Content size: {responseString.Length}");
                        Console.Write($"Content: {responseString}");

                        return responseString;
                    }
                    catch
                    {
                        throw;
                    }
                }
            }
        }

        private static bool ServerCertificateValidation(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
        {
            // It is possible inpect the certificate provided by server
            Console.WriteLine($"Requested URI: {requestMessage.RequestUri}");
            Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            Console.WriteLine($"Issuer: {certificate.Issuer}");
            Console.WriteLine($"Subject: {certificate.Subject}");

            // Based on the custom logic it is possible to decide whether the client considers certificate valid or not
            Console.WriteLine($"Errors: {sslErrors}");
            
            return sslErrors == SslPolicyErrors.None;
        }

        private static bool AcceptServerCertificate(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
        {
            // It is possible inpect the certificate provided by server
            Console.WriteLine($"Requested URI: {requestMessage.RequestUri}");
            Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            Console.WriteLine($"Issuer: {certificate.Issuer}");
            Console.WriteLine($"Subject: {certificate.Subject}");

            // Based on the custom logic it is possible to decide whether the client considers certificate valid or not
            Console.WriteLine($"Errors: {sslErrors}");

            return true;
        }




    }
}

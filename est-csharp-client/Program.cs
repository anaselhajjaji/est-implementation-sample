using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace EstClient
{
    class Program
    {
        const string caEndpoint = "https://est-server:8443/.well-known/est/cacerts";

        static async Task Main(string[] args)
        {
            await GetEstCaCertificate();
        }

        static async Task GetEstCaCertificate()
        {
            var caCertP7 = await MakeHttpCall(caEndpoint, AcceptServerCertificate);

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

        private static async Task<string> MakeHttpCall(string endpoint, Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> serverCertValidationCallBack)
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

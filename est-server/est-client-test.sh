#!/bin/sh

echo "STEP 1"
echo "Retrieve the CA certificates in insecure mode to establish an explicit trust anchor for subsequent EST operations"
echo "Obtain and store the full CA certificates chain, since we'll use it shortly to demonstrate reenrollment." 
echo "Since we now have an explicit trust anchor, we can use it instead of the -insecure option. Since we're storing the full chain, we don't use the -rootout."
estclient cacerts -server localhost:8443 -insecure -rootout -out anchor.pem
estclient cacerts -server localhost:8443 -explicit anchor.pem -out cacerts.pem

echo "CASE 1"
echo "Enrolling with an existing private key"
echo "First we generate a new private key, here using openssl"
openssl genrsa 4096 > key.pem

echo "Generate a PKCS#10 certificate signing request, and enroll using the explicit trust anchor we previously obtained"
estclient csr -key key.pem -cn 'John Doe' -emails 'john@doe.com' -out csr.pem
estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -out cert.pem

echo "CASE 2"
echo "Enrolling with a server-generated private key"
estclient serverkeygen -server localhost:8443 -explicit anchor.pem -cn 'Jane Doe' -out cert2.pem -keyout key2.pem

echo "CASE 3"
echo "Reenrolling..."
echo "Append those CA certificates to the certificate we received, and use that chain to reenroll"
cat cert.pem cacerts.pem >> certs.pem
estclient reenroll -server localhost:8443 -explicit anchor.pem -key key.pem -certs certs.pem -out newcert.pem

echo "Showing the created files"
ls .
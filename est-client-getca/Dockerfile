FROM golang:1.13

WORKDIR /app

RUN go mod init est-client-getca
RUN go get -u github.com/globalsign/est
RUN go install github.com/globalsign/est/cmd/estclient

# retrieve the CA certificates in insecure mode to establish an explicit trust anchor for subsequent EST operations
RUN estclient cacerts -server est-cerver:8443 -insecure -rootout -out anchor.pem

# obtain and store the full CA certificates chain, since we'll use it shortly to demonstrate reenrollment. 
# Since we now have an explicit trust anchor, we can use it instead of the -insecure option. Since we're storing the full chain, we don't use the -rootout
RUN estclient cacerts -server localhost:8443 -explicit anchor.pem -out cacerts.pem
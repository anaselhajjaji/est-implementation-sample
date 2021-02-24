FROM golang:1.13

WORKDIR /app

RUN go mod init est-server
RUN go get -u github.com/globalsign/est@v1.0.6
RUN go install github.com/globalsign/est/cmd/estserver

CMD ["estserver"]
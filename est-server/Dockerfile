FROM golang:1.14

WORKDIR /app

RUN go mod init est-server
RUN go get -u github.com/globalsign/est
RUN go install github.com/globalsign/est/cmd/estserver

CMD ["estserver"]
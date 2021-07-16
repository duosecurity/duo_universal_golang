FROM golang:latest
EXPOSE 8080
WORKDIR /go/src/app
ADD . .

RUN go mod tidy

WORKDIR /go/src/app/example
ENTRYPOINT ["go", "run", "main.go"]
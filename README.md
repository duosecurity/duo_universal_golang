# Duo Universal Go library

This SDK allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any Golang web login form.


What's included:
* `duouniversal` - The Golang Duo SDK for interacting with the Duo Universal Prompt
* `example` - An example Go application with Duo integrated

## Tested Against Go Versions: 
	- 1.16

## TLS 1.2 and 1.3 Support

Duo_universal_golang uses the Go cryptography library for TLS operations. Go versions 1.13 and higher support both TLS 1.2 and 1.3.

## Getting Started
To use the SDK in your existing development environment, install it using Go Modules
```
go mod init example
go get github.com/duosecurity/duo_universal_golang/duouniversal
```
Once it's installed, see our developer documentation at https://duo.com/docs/duoweb and `example/main.go` in this repo for guidance on integrating Duo 2FA into your web application.
See https://github.com/duosecurity/duo_python/pull/57 for a step-by-step example of migrating an existing WebSDK2 integration to the Universal SDK.

## Contribute
To contribute, fork this repo and make a pull request with your changes when they are ready.

Install the SDK from source:
```
cd duouniversal/
go build
```

## Tests
```
cd duouniversal/
go test
```

## Format
To run formatter
```
go fmt
```

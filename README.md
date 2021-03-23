# Duo Universal PHP library

This SDK allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any Golang web login form.


What's included:
* `duo_universal` - The Golang Duo SDK for interacting with the Duo Universal Prompt
* `main.go` - An example PHP application with Duo integrated

## Getting started

Go into `duo_universal/` and install the `duouniversal` package:
```
go build
```

## Contribute
To contribute, fork this repo and make a pull request with your changes when they are ready.

Install the SDK from source:
```
cd duo_universal/
go build
```

## Tests
```
cd duo_universal/
go test
```

## Format
To run formatter
```
go fmt
```

## Demo
### Setup
Change to the "duo_universal" directory
```
cd duo_universal
```

Install the `duouniversal` package
```
go build
```

Then, create a `Web SDK` application in the Duo Admin Panel. See https://duo.com/docs/protecting-applications for more details.

### Using the App

1. Copy the Client ID, Client Secret, and API Hostname values for your `Web SDK` application into the `duo_config.json` file.
1. Change back to the root directory
    ```
    cd ..
    ```
1. Start the app.
    ```
    go run main.go
    ```
1. Navigate to http://localhost:8080.
1. Log in with the user you would like to enroll in Duo or with an already enrolled user (any password will work).

package duouniversal

import (
	"crypto/rand"
	"math/big"
)

const defaultStateLength = 36

// StateCharacters is the set of possible characters used in the random state
const stateCharacters = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	"1234567890"

type Client struct {
}

func NewClient() *Client {
	return &Client{}
}

// Return a cryptographically-secure string of random characters
// with the default length
func (client *Client) generateState() (string, error) {
	return client.generateStateWithLength(defaultStateLength)
}

// Return a cryptographically-secure string of random characters
// suitable for use in state values.
// length is the number of characters in the randomly generated string
func (client *Client) generateStateWithLength(length int) (string, error) {
	result := make([]byte, length)
	possibleCharacters := int64(len(stateCharacters))
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(possibleCharacters))
		if err != nil {
			return "", err
		}
		result[i] = stateCharacters[n.Int64()]
	}
	return string(result), nil
}

package duouniversal

import "testing"

func TestRandomStateLength(t *testing.T) {
	client := NewClient()
	output, err := client.generateStateWithLength(100)
	if err != nil {
		t.Error(err)
	}
	if len(output) != 100 {
		t.Errorf("Expected output of length 100, got '%d'", len(output))
	}
}

func TestRandomStateLengthZero(t *testing.T) {
	client := NewClient()
	output, err := client.generateStateWithLength(0)
	if err != nil {
		t.Error(err)
	}
	if len(output) != 0 {
		t.Errorf("Expected output of length 0, got '%d'", len(output))
	}
}

func TestRandomStateLengthRandom(t *testing.T) {
	client := NewClient()
	output1, err := client.generateStateWithLength(60)
	if err != nil {
		t.Error(err)
	}
	output2, err := client.generateStateWithLength(60)
	if err != nil {
		t.Error(err)
	}
	if output1 == output2 {
		t.Errorf("State generation output two identical strings, '%s'", output1)
	}
}

func TestRandomStateDefaultLength(t *testing.T) {
	client := NewClient()
	output, err := client.generateState()
	if err != nil {
		t.Error(err)
	}
	if len(output) != defaultStateLength {
		t.Errorf("Expected output of length %d but got %d", defaultStateLength, len(output))
	}
}

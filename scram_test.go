package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestSCRAMSHA256(t *testing.T) {
	password := "testpassword"
	iterations := 4096

	scramHash, err := SCRAMSHA256(password, iterations)
	if err != nil {
		t.Fatalf("Failed to generate SCRAM-SHA-256 hash: %v", err)
	}

	// Verify SCRAM-SHA-256 hash format
	if !strings.HasPrefix(scramHash, "SCRAM-SHA-256$") {
		t.Errorf("Expected hash to start with 'SCRAM-SHA-256$', got %s", scramHash)
	}

	// Verify iteration count in hash
	parts := strings.Split(scramHash, "$")
	if len(parts) < 2 {
		t.Fatalf("Invalid hash format: %s", scramHash)
	}

	iterationsInHash := parts[1]
	if iterationsInHash != "4096" {
		t.Errorf("Expected iterations to be '4096', got %s", iterationsInHash)
	}

	// Verify salt, stored key, and server key are Base64-encoded
	hashBody := parts[2]
	subParts := strings.Split(hashBody, ":")
	if len(subParts) != 3 {
		t.Fatalf("Invalid hash body format: %s", hashBody)
	}

	for _, part := range subParts {
		if _, err := base64.StdEncoding.DecodeString(part); err != nil {
			t.Errorf("Part of hash is not valid Base64: %s", part)
		}
	}
}

func TestHMACSHA256(t *testing.T) {
	key := []byte("testkey")
	message := []byte("testmessage")
	expected := "b1b4c3fb5899973e925a5784de31754f74b1a4e4ecbcb3e10c406f5c256b1a5f"

	result := hmacSHA256(key, message)
	resultHex := fmt.Sprintf("%x", result)

	if resultHex != expected {
		t.Errorf("HMAC-SHA-256 mismatch: expected %s, got %s", expected, resultHex)
	}
}

func TestInvalidIterations(t *testing.T) {
	password := "testpassword"
	iterations := -1

	_, err := SCRAMSHA256(password, iterations)
	if err == nil {
		t.Fatal("Expected an error for negative iterations, but got none")
	}
}

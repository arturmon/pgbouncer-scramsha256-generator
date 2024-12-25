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

	// Split the SCRAM hash into its components
	parts := strings.SplitN(scramHash, "$", 2) // Split only once by the first '$'
	if len(parts) != 2 {
		t.Fatalf("Invalid hash format: expected 2 parts, got %d parts", len(parts))
	}

	// Verify the first part is 'SCRAM-SHA-256'
	if parts[0] != "SCRAM-SHA-256" {
		t.Errorf("Expected hash prefix 'SCRAM-SHA-256', got '%s'", parts[0])
	}

	// Split the second part by ':' to check iterations, salt, stored_key, and server_key
	hashBody := parts[1]
	subParts := strings.Split(hashBody, ":")
	if len(subParts) != 4 {
		t.Fatalf("Invalid hash body format: expected 4 parts, got %d parts", len(subParts))
	}

	// Verify that the iterations are correct
	if subParts[0] != "4096" {
		t.Errorf("Expected iterations to be '4096', got '%s'", subParts[0])
	}

	// Verify salt, stored key, and server key are Base64-encoded
	for _, part := range subParts[1:] {
		if _, err := base64.StdEncoding.DecodeString(part); err != nil {
			t.Errorf("Part of hash is not valid Base64: %s", part)
		}
	}
}

func TestHMACSHA256(t *testing.T) {
	key := []byte("testkey")
	message := []byte("testmessage")
	expected := "65a82b1be740170b4a941a21489d18233abd3eae75dc38cea54abbb778df8622" // Updated expected value

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

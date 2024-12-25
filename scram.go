package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// SCRAMSHA256 generates a SCRAM-SHA-256 hash
func SCRAMSHA256(password string, iterations int) (string, error) {
	// Validate iterations (must be greater than 0)
	if iterations <= 0 {
		return "", fmt.Errorf("iterations must be greater than 0")
	}
	// Generate a random 16-byte salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("error generating salt: %v", err)
	}

	// Derive the salted password using PBKDF2
	saltedPassword := pbkdf2.Key([]byte(password), salt, iterations, sha256.Size, sha256.New)

	// Generate the client key
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))

	// Compute the stored key
	storedKey := sha256.Sum256(clientKey)

	// Generate the server key
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))

	// Format the SCRAM hash
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	storedKeyB64 := base64.StdEncoding.EncodeToString(storedKey[:])
	serverKeyB64 := base64.StdEncoding.EncodeToString(serverKey)

	scramHash := fmt.Sprintf("SCRAM-SHA-256$%d:%s:%s:%s", iterations, saltB64, storedKeyB64, serverKeyB64)
	return scramHash, nil
}

// hmacSHA256 computes an HMAC-SHA-256
func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func printHelp() {
	fmt.Println(`Usage:
  scram [options]

Options:
  --password      The password to hash (required)
  --iterations    Number of PBKDF2 iterations (default: 4096)
  --help          Display this help message

Examples:
  Generate a SCRAM-SHA-256 hash with default iterations:
    ./scram --password="mypassword"

  Generate a SCRAM-SHA-256 hash with custom iterations:
    ./scram --password="mypassword" --iterations=10000`)
}

func main() {
	// Define flags
	passwordPtr := flag.String("password", "", "Password to hash (required)")
	iterationsPtr := flag.String("iterations", "4096", "Number of PBKDF2 iterations (default: 4096)")
	helpPtr := flag.Bool("help", false, "Display help message")

	flag.Usage = printHelp // Override default usage

	// Parse flags
	flag.Parse()

	// Handle --help
	if *helpPtr {
		printHelp()
		os.Exit(0)
	}

	// Validate password
	if *passwordPtr == "" {
		fmt.Println("Error: --password is required")
		printHelp()
		os.Exit(1)
	}

	// Convert iterations to integer
	iterations, err := strconv.Atoi(*iterationsPtr)
	if err != nil || iterations <= 0 {
		log.Fatalf("Invalid --iterations value: %v", *iterationsPtr)
	}

	// Generate SCRAM hash
	scramHash, err := SCRAMSHA256(*passwordPtr, iterations)
	if err != nil {
		log.Fatalf("Error generating SCRAM hash: %v", err)
	}

	// Print the result
	fmt.Println("SCRAM-SHA-256 Hash:")
	fmt.Println(scramHash)
}

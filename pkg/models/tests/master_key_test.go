package master_key_test

import (
	"testing"

	master_key "github.com/duvrdx/oasys-crypto/pkg/models"
)

func TestNewMasterKey(t *testing.T) {
	password := "password"
	keySize := 32

	mk, err := master_key.NewMasterKey(password, keySize)
	if err != nil {
		t.Fatalf("Error creating master key: %v", err)
	}

	if mk == nil {
		t.Fatalf("Expected a non-nil master key")
	}

	if len(mk.Key) != keySize {
		t.Fatalf("Expected key length %d, got %d", keySize, len(mk.Key))
	}

	if len(mk.Salt) != keySize {
		t.Fatalf("Expected salt length %d, got %d", keySize, len(mk.Salt))
	}

	if mk.KeySize != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, mk.KeySize)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	password := "password"
	keySize := 32

	mk, err := master_key.NewMasterKey(password, keySize)
	if err != nil {
		t.Fatalf("Error creating master key: %v", err)
	}

	plaintext := "hello"
	encrypted, err := mk.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Error encrypting: %v", err)
	}

	decrypted, err := mk.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Error decrypting: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Expected decrypted text %s, got %s", plaintext, decrypted)
	}
}

func TestVerifyDerivedKey(t *testing.T) {
	password := "password"
	keySize := 32

	mk, err := master_key.NewMasterKey(password, keySize)
	if err != nil {
		t.Fatalf("Error creating master key: %v", err)
	}

	if !mk.VerifyDerivedKey(password) {
		t.Fatalf("Failed to verify derived key")
	}
}

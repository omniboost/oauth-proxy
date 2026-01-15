package types

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// We only support AES-256-CBC for now
// OptionallyEncryptedString mimics Laravel's encrypted string format

var AppKey []byte

func init() {
	key := os.Getenv("APP_KEY")
	if strings.HasPrefix(key, "base64:") {
		AppKey, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(key, "base64:"))
	} else {
		AppKey = []byte(key)
	}
	if len(AppKey) == 0 {
		panic("APP_KEY environment variable is not set")
	}
}

type OptionallyEncryptedString string

type optionallyEncryptedStringInternal struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	Mac   string `json:"mac"`
	Tag   string `json:"tag"`
}

var newIV = func() string {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(fmt.Sprintf("failed to generate IV: %v", err))
	}
	return base64.StdEncoding.EncodeToString(iv)
}

func encryptString(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}

	inner := optionallyEncryptedStringInternal{
		IV: newIV(),
	}

	iv, err := base64.StdEncoding.DecodeString(inner.IV)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(AppKey)
	if err != nil {
		return "", err
	}

	// Pad plaintext to block size
	plaintext := PKCS5Padding([]byte(plain), block.BlockSize())
	ciphertext := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	inner.Value = base64.StdEncoding.EncodeToString(ciphertext)
	inner.Mac = hashString(inner.IV, inner.Value)
	inner.Tag = "" // Not used in CBC mode

	j, err := jsoniter.Marshal(inner)
	return base64.StdEncoding.EncodeToString(j), nil
}

func hashString(iv, value string) string {
	h := hmac.New(sha256.New, AppKey)
	h.Write(append([]byte(iv), []byte(value)...))
	return hex.EncodeToString(h.Sum(nil))
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func decryptString(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	var inner optionallyEncryptedStringInternal
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		// if it's not base64, return as is
		return encrypted, nil
	}
	if err := jsoniter.Unmarshal(decoded, &inner); err != nil {
		// if it's not json, return as is
		return encrypted, nil
	}
	if inner.IV == "" || inner.Value == "" || inner.Mac == "" {
		// if any field is missing, return as is
		return encrypted, nil
	}

	expectedMac := hashString(inner.IV, inner.Value)
	if !hmac.Equal([]byte(expectedMac), []byte(inner.Mac)) {
		return "", errors.New("invalid MAC for encrypted string")
	}

	iv, err := base64.StdEncoding.DecodeString(inner.IV)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(inner.Value)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(AppKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	decrypted := string(PKCS5Trimming(plaintext))

	return decrypted, nil
}

func (oes *OptionallyEncryptedString) Scan(value interface{}) error {
	if value == nil {
		*oes = OptionallyEncryptedString("")
		return nil
	}

	switch v := value.(type) {
	case string:
		decrypted, err := decryptString(v)
		if err != nil {
			return err
		}
		*oes = OptionallyEncryptedString(decrypted)
		return nil
	case []byte:
		decrypted, err := decryptString(string(v))
		if err != nil {
			return err
		}
		*oes = OptionallyEncryptedString(decrypted)
		return nil
	}
	return errors.New("optionally encrypted string not supported")
}

func (oes OptionallyEncryptedString) Value() (driver.Value, error) {
	return encryptString(string(oes))
}

// ErrInvalidOptionallyEncryptedString is the invalid OptionallyEncryptedString error.
type ErrInvalidOptionallyEncryptedString string

// Error satisfies the error interface.
func (err ErrInvalidOptionallyEncryptedString) Error() string {
	return fmt.Sprintf("invalid ErrInvalidOptionallyEncryptedString (%s)", string(err))
}

/*
 * aes.go - Chiffrement AES-256-CBC
 *
 * Compatible avec l'implémentation côté agent.
 */
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// DefaultKey est la clé AES par défaut (32 bytes = AES-256)
// En prod, cette clé serait générée et injectée dans les payloads
var DefaultKey = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// DefaultIV est l'IV par défaut (16 bytes)
var DefaultIV = []byte{
	0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
	0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
}

// PKCS7Padding ajoute le padding PKCS#7
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS7Unpadding enlève le padding PKCS#7
func PKCS7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding: empty data")
	}

	padding := int(data[length-1])
	if padding > length || padding > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}

	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:length-padding], nil
}

// Encrypt chiffre les données avec AES-256-CBC
func Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Ajoute le padding
	plaintext = PKCS7Padding(plaintext, aes.BlockSize)

	// Chiffre
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// Decrypt déchiffre les données avec AES-256-CBC
func Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	// Déchiffre
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Enlève le padding
	return PKCS7Unpadding(plaintext)
}

// EncryptWithDefaults utilise la clé et l'IV par défaut
func EncryptWithDefaults(plaintext []byte) ([]byte, error) {
	return Encrypt(plaintext, DefaultKey, DefaultIV)
}

// DecryptWithDefaults utilise la clé et l'IV par défaut
func DecryptWithDefaults(ciphertext []byte) ([]byte, error) {
	return Decrypt(ciphertext, DefaultKey, DefaultIV)
}

// GenerateKey génère une clé AES-256 aléatoire
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateIV génère un IV aléatoire
func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

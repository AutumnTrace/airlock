package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

const pubPrefix = "ed25519:"

// GenerateKey makes a new signing key and returns it PEM-encoded (PKCS #8)
// along with its public half in airlock's text form.
func GenerateKey() (privPEM []byte, pub string, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), PublicKeyString(pk), nil
}

// LoadPrivateKey reads a PEM file written by GenerateKey.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return sk, nil
}

// PublicKeyString renders a public key as "ed25519:<base64>".
func PublicKeyString(pk ed25519.PublicKey) string {
	return pubPrefix + base64.StdEncoding.EncodeToString(pk)
}

// ParsePublicKey accepts "ed25519:<base64>", or the path of a file holding
// that string.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, pubPrefix) {
		b, err := os.ReadFile(s)
		if err != nil {
			return nil, fmt.Errorf("public key must be %q or a file containing it", pubPrefix+"...")
		}
		s = strings.TrimSpace(string(b))
	}
	if !strings.HasPrefix(s, pubPrefix) {
		return nil, errors.New("public key must look like ed25519:<base64>")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, pubPrefix))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var (
	RSAPrivateKey *rsa.PrivateKey
	JWK           map[string]interface{}
	KeyID         = "auth-key-1" // Static ID for now, can be rotated later
)

// InitKeys loads or generates the RSA keypair used for signing OIDC JWTs.
func InitKeys() error {
	if err := os.MkdirAll("keys", 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	keyPath := "keys/rsa_private.pem"

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Println("Generating new RSA-2048 keypair...")
		var err error
		RSAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		privBytes := x509.MarshalPKCS1PrivateKey(RSAPrivateKey)
		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		})

		if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
			return err
		}
	} else {
		privPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(privPEM)
		if block == nil {
			return fmt.Errorf("failed to parse PEM block containing the key")
		}
		RSAPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	}

	// Generate JWK representation
	pubKey := RSAPrivateKey.Public().(*rsa.PublicKey)
	JWK = map[string]interface{}{
		"kty": "RSA",
		"kid": KeyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	return nil
}

// SignJWT creates and signs a JWT with the given claims.
func SignJWT(claims jwt.MapClaims) (string, error) {
	if RSAPrivateKey == nil {
		return "", fmt.Errorf("RSA private key not initialized")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = KeyID
	return token.SignedString(RSAPrivateKey)
}

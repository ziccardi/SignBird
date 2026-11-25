package keycert

import (
	"crypto"
	"net/http"
)

type digestCapability struct {
	Algorithm   string `json:"algorithm"`
	DigestBytes int    `json:"digestBytes"`
}

type keyCapability struct {
	Algorithm       string             `json:"algorithm"`
	SignatureScheme string             `json:"signatureScheme"`
	HashAlgorithms  []digestCapability `json:"hashAlgorithms"`
}

var supportedHashes = []digestCapability{
	{Algorithm: "SHA-256", DigestBytes: crypto.SHA256.Size()},
	{Algorithm: "SHA-512", DigestBytes: crypto.SHA512.Size()},
}

var supportedKeys = []keyCapability{
	{Algorithm: rsa2048, SignatureScheme: "RSASSA-PKCS1-v1_5", HashAlgorithms: supportedHashes},
	{Algorithm: ecdsaP256, SignatureScheme: "ECDSA", HashAlgorithms: supportedHashes},
	{Algorithm: ecdsaP521, SignatureScheme: "ECDSA", HashAlgorithms: supportedHashes},
}

func signingScheme(algorithm string) string {
	for _, capability := range supportedKeys {
		if capability.Algorithm == algorithm {
			return capability.SignatureScheme
		}
	}
	return ""
}

func (s *service) capabilities(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, supportedKeys)
}

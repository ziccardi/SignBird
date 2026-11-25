package keycert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

type keystore struct {
	password string
}

func newID() string {
	var bits [16]byte
	rand.Read(bits[:])
	return hex.EncodeToString(bits[:])
}

func asPEM(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

const (
	rsa2048   = "RSA-2048"
	ecdsaP256 = "ECDSA-P256"
	ecdsaP521 = "ECDSA-P521"
)

func keyAlgorithm(public crypto.PublicKey) string {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() == 2048 {
			return rsa2048
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return ecdsaP256
		case elliptic.P521():
			return ecdsaP521
		}
	}
	return ""
}

func (s keystore) decode(data []byte) (crypto.Signer, error) {
	key, _, err := pkcs12.Decode(data, s.password)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok || keyAlgorithm(signer.Public()) == "" {
		return nil, errors.New("unsupported key in the PKCS#12 container")
	}
	return signer, nil
}

func (s keystore) generate(algorithm string) ([]byte, error) {
	var key crypto.Signer
	var err error
	switch algorithm {
	case rsa2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case ecdsaP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ecdsaP521:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, errors.New("unsupported key algorithm")
	}
	if err != nil {
		return nil, err
	}
	// PKCS#12 contains a placeholder certificate. Issued certificates live in PostgreSQL.
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now, NotAfter: now.AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return pkcs12.Modern.Encode(key, cert, nil, s.password)
}

func publicKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	return asPEM("PUBLIC KEY", der), nil
}

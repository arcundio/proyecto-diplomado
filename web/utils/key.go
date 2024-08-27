package utils

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
)

// Convertir cadena de llave privada PEM a objeto de llave privada
func ParsePrivateKey(pemData string) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(pemData))
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("invalid key type")
    }

    privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return privKey, nil
}

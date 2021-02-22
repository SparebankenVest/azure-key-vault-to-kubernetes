package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

type ClientCertificate struct {
	CA  []byte
	Crt []byte
	Key []byte
}

func generateClientCert(mutationID types.UID, validMonths int, caCert, caKey []byte) (*ClientCertificate, error) {
	klog.V(4).InfoS("creating x509 key pair for ca cert and key")
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}

	klog.V(4).InfoS("parse certificate")
	x509Ca, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}

	klog.V(4).InfoS("generating client key")
	clientKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	klog.V(4).InfoS("generating serial number")
	now := time.Now()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"akv2k8s"},
			CommonName:   string(mutationID),
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, validMonths, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	klog.V(4).InfoS("crating x509 certificate")
	certByte, err := x509.CreateCertificate(rand.Reader, &template, x509Ca, &clientKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certByte,
	}
	pemCert := pem.EncodeToMemory(certBlock)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return nil, err
	}

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	pemKey := pem.EncodeToMemory(keyBlock)

	return &ClientCertificate{
		CA:  caCert,
		Crt: pemCert,
		Key: pemKey,
	}, nil
}

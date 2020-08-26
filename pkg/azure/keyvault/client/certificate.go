/*
Copyright Sparebanken Vest

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

// CertificateKeyType contains the private key type
type CertificateKeyType string

const (
	// CertificateKeyTypeRsa represents private key type RSA
	CertificateKeyTypeRsa CertificateKeyType = "rsa"

	// CertificateKeyTypeEcdsa represents private key type ECDSA
	CertificateKeyTypeEcdsa = "ecdsa"
)

// Certificate handles data on Certificates from Azure Key Vault
type Certificate struct {
	// Has the complete certificate with both public and private keys, if both exists
	Certificates []*x509.Certificate

	PrivateKeyRaw   []byte
	PrivateKeyRsa   *rsa.PrivateKey
	PrivateKeyEcdsa *ecdsa.PrivateKey

	raw []byte

	PrivateKeyType CertificateKeyType

	// Indicate if Certificate has private key
	HasPrivateKey bool
}

// NewCertificateFromPem creates a new Certificate from a base64 encoded pem string
func NewCertificateFromPem(pem string) (*Certificate, error) {

	// privateDer, rest := pem.Decode([]byte(c.cert))
	// publicDer, _ := pem.Decode(rest)

	cert, err := importPem(pem, false)
	if err != nil {
		return nil, err
	}

	cert.raw = []byte(pem)

	return cert, nil
}

// NewCertificateFromPfx creates a new Certificate from a PFX certificate
func NewCertificateFromPfx(pfx []byte, ensureServerFirst bool) (*Certificate, error) {
	pemList, err := pkcs12.ToPEM(pfx, "")

	if err != nil {
		return nil, fmt.Errorf("failed to convert pfx to pem, error: %+v", err)
	}

	var mergedPems bytes.Buffer
	for _, pemCert := range pemList {
		mergedPems.WriteString(string(pem.EncodeToMemory(pemCert)))
	}

	cert, err := importPem(mergedPems.String(), ensureServerFirst)
	if err != nil {
		return nil, err
	}

	cert.raw = pfx
	return cert, nil
}

// NewCertificateFromDer creates a new Certificate from a public cer key
func NewCertificateFromDer(der []byte) (*Certificate, error) {
	var cert Certificate
	pubCerts, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse der certificate, error: *%+v", err)
	}

	cert.HasPrivateKey = false
	cert.Certificates = append(cert.Certificates, pubCerts...)

	cert.raw = der
	return &cert, nil
}

// ExportPrivateKeyAsPem returns a pem formatted certificate
func (cert *Certificate) ExportPrivateKeyAsPem() ([]byte, error) {
	if !cert.HasPrivateKey {
		return nil, fmt.Errorf("certificate has no private key")
	}

	var derKey []byte
	var err error

	switch cert.PrivateKeyType {
	case CertificateKeyTypeRsa:
		derKey = x509.MarshalPKCS1PrivateKey(cert.PrivateKeyRsa)
	case CertificateKeyTypeEcdsa:
		derKey, err = x509.MarshalECPrivateKey(cert.PrivateKeyEcdsa)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("private key type '%s' currently not supported for pem export", cert.PrivateKeyType)
	}

	privKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derKey,
	}
	return pem.EncodeToMemory(privKeyBlock), nil
}

// ExportPublicKeyAsPem returns a pem formatted certificate
func (cert *Certificate) ExportPublicKeyAsPem() ([]byte, error) {
	if len(cert.Certificates) == 0 {
		return nil, fmt.Errorf("certificate has no public key")
	}

	var certs strings.Builder
	for _, pubCert := range cert.Certificates {
		privKeyBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pubCert.Raw,
		}

		certs.Write(pem.EncodeToMemory(privKeyBlock))
	}

	return []byte(certs.String()), nil
}

// ExportRaw returns the raw format of the original certificate
func (cert *Certificate) ExportRaw() []byte {
	return cert.raw
}

func importPem(pemCert string, ensureServerFirst bool) (*Certificate, error) {
	var cert Certificate
	var publicDers [][]byte
	var joinedPublicDers []byte
	var err error
	raw := []byte(pemCert)

	for {
		pemBlock, rest := pem.Decode(raw)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type == "CERTIFICATE" {
			publicDers = append(publicDers, pemBlock.Bytes)
		} else {
			err = parsePrivateKey(pemBlock.Bytes, &cert)
			if err != nil {
				return nil, err
			}
		}
		raw = rest
	}

	if ensureServerFirst && len(publicDers) > 1 {
		publicDers = append(
			publicDers[len(publicDers)-1:],
			publicDers[0:len(publicDers)-1]...,
		)
	}

	for _, der := range publicDers {
		joinedPublicDers = append(joinedPublicDers, der...)
	}

	cert.Certificates, err = x509.ParseCertificates(joinedPublicDers)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func parsePrivateKey(der []byte, out *Certificate) error {
	var err error

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		out.HasPrivateKey = true
		out.PrivateKeyRaw = der
		out.PrivateKeyRsa = key
		out.PrivateKeyType = CertificateKeyTypeRsa
		return nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			out.HasPrivateKey = true
			out.PrivateKeyRaw = der
			out.PrivateKeyRsa = key
			out.PrivateKeyType = CertificateKeyTypeRsa
			return nil
		case *ecdsa.PrivateKey:
			out.HasPrivateKey = true
			out.PrivateKeyRaw = der
			out.PrivateKeyEcdsa = key
			out.PrivateKeyType = CertificateKeyTypeEcdsa
			return nil
		default:
			return fmt.Errorf("unknown private key type found while parsing pkcs#8 - only rsa and ecdsa supported")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		out.HasPrivateKey = true
		out.PrivateKeyRaw = der
		out.PrivateKeyEcdsa = key
		out.PrivateKeyType = CertificateKeyTypeEcdsa
		return nil
	}
	return fmt.Errorf("Failed to parse private key, error: %+v", err)
}

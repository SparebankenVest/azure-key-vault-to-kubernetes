package vault

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	azureKeyVaultSecretv1alpha1 "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
)

// AzureKeyVaultService provide interaction with Azure Key Vault
type AzureKeyVaultService struct {
}

// NewAzureKeyVaultService creates a new AzureKeyVaultService using built in Managed Service Identity for authentication
func NewAzureKeyVaultService() *AzureKeyVaultService {
	return &AzureKeyVaultService{}
}

// GetSecret returns a secret from Azure Key Vault
func (a *AzureKeyVaultService) GetSecret(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
	//Get secret value from Azure Key Vault
	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	var vaultSecret string

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)

	switch strings.ToLower(secret.Spec.Vault.ObjectType) {
	case "certificate":
		secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

		if err != nil {
			return "", fmt.Errorf("failed to get secret from azure key vault, error: %+v", err)
		}

		keyPair := *secretBundle.Value

		pemBlock, derBlock := pem.Decode([]byte(keyPair))
		log.Infof("pem block: %s", pemBlock)
		log.Infof("der block: %s", derBlock)

		return keyPair, nil
		// cert, err := x509.ParseCertificate(*secretBundle.Cer)
		// if err != nil {
		// 	return "", fmt.Errorf("failed to parse certificate from Azure Key Vault, error: %+v", err)
		// }
		//
		// pubKey := string(CertToPEM(cert))
		//
		// keyBundle, err := vaultClient.GetKey(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")
		// if err != nil {
		// 	return "", fmt.Errorf("failed to get certificate key from azure key vault, error: %+v", err)
		// }
		//
		// log.Infof("private key format: %s", keyBundle.Key.Kty)
		//
		// // nb, err := base64.RawURLEncoding.DecodeString(*keyBundle.Key.N)
		// // if err != nil {
		// // 	log.Errorf("failed to decode base64: %+v", err)
		// // }
		//
		// log.Infof("n: %s", *keyBundle.Key.N)
		//
		// // pk := &rsa.PublicKey{
		// // 	N: new(big.Int).SetBytes(nb),
		// // }
		//
		// rsa.
		// pk, err := x509.ParsePKCS1PrivateKey([]byte(*keyBundle.Key.N))
		// if err != nil {
		// 	log.Errorf("failed to parse pkcs1 private key: %+v", err)
		// }
		//
		// // log.Infof("pkcs1 private key: %s", pk)
		//
		// // privKeyDer, err := x509.ParsePKCS1PrivateKey(*keyBundle.Key.N)
		// // if err != nil {
		// // 	log.Errorf("failed to parse private key from Azure Key Vault, error: %+v", err)
		// // }
		// privKeyPem := x509.MarshalPKCS1PrivateKey(pk)
		// log.Infof("private key: %s", privKeyPem)
		//
		// // rsaPrivateKeyBase64Decoded, err := base64.RawURLEncoding.DecodeString(*keyBundle.Key.N)
		// // if err != nil {
		// // 	return "", fmt.Errorf("failed to decode base64 private from Azure Key Vault key bundle, error: %+v", err)
		// // }
		// // log.Infof("base64 private key decoded: %s", rsaPrivateKeyBase64Decoded)
		// //
		// // rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(rsaPrivateKeyBase64Decoded)
		// // if err != nil {
		// // 	return "", fmt.Errorf("failed to parse private key, error: %+v", err)
		// // }
		// //
		// // privateKey := string(x509.MarshalPKCS1PrivateKey(rsaPrivateKey))
		// // privateKey := string(base64.RawStdEncoding.Encode(dst, src) privateKeyByte)
		//
		// // privateKey, err := x509.ParsePKCS8PrivateKey(cert.RawTBSCertificate)
		// // if err != nil {
		// // 	return "", fmt.Errorf("failed to parse pkcs8 private key, error: %+v", err)
		// // }
		// //
		// // privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		// // if err != nil {
		// // 	return "", fmt.Errorf("failed to marshal pkcs8 private key, error: %+v", err)
		// // }
		// //
		// // pemdata := pem.EncodeToMemory(&pem.Block{
		// // 	Type:  "RSA PRIVATE KEY",
		// // 	Bytes: privBytes,
		// // },
		// // )
		//
		// return string(pubKey), nil
		//
		// // return fmt.Printf(privateKey), nil
		//
		// // pubKey := cert.PublicKey.(*rsa.PublicKey)
		//
		// // switch cert.PublicKeyAlgorithm {
		// // case x509.RSA:
		// // }
		// // cert.PublicKey
		// // vaultSecret = cert.Subject.String()
		// // vaultClient.GetKey(context.Background(), baseURL, secretBundle.Kid, keyVersion)
		// // vaultSecret = bytes.NewBuffer(*secretBundle.Cer).String() //string(*secretBundle.Cer)
		// // decSecret, err := base64.StdEncoding.DecodeString(vaultSecret)
		// // if err != nil {
		// // 	return "", fmt.Errorf("failed to base64 decode Azure Key Vault certificate for %s / %s, error: %+v", secret.Namespace, secret.Name, err)
		// // }
		// // vaultSecret = string(decSecret)
	default:
		secretBundle, err := vaultClient.GetSecret(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

		if err != nil {
			return "", err
		}
		vaultSecret = *secretBundle.Value
	}

	return vaultSecret, nil
}

// GetCertificate returns a certificate from Azure Key Vault
func (a *AzureKeyVaultService) getCertificate(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
	//Get secret value from Azure Key Vault
	vaultClient, err := a.getClient("https://vault.azure.net")
	if err != nil {
		return "", err
	}

	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
	certBundle, err := vaultClient.GetCertificate(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")

	if err != nil {
		return "", err
	}

	return string(*certBundle.Cer), nil
}

// // GetSecret returns a secret from Azure Key Vault
// func (a *AzureKeyVaultService) GetKey(secret *azureKeyVaultSecretv1alpha1.AzureKeyVaultSecret) (string, error) {
// 	//Get secret value from Azure Key Vault
// 	vaultClient, err := a.getClient("https://vault.azure.net")
// 	if err != nil {
// 		return "", err
// 	}
//
// 	baseURL := fmt.Sprintf("https://%s.vault.azure.net", secret.Spec.Vault.Name)
// 	secretPack, err := vaultClient.GetKey(context.Background(), baseURL, secret.Spec.Vault.ObjectName, "")
//
// 	if err != nil {
// 		return "", err
// 	}
// 	return *secretPack.Value, nil
// }

func (a *AzureKeyVaultService) getClient(resource string) (*keyvault.BaseClient, error) {
	authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(resource)
	if err != nil {
		return nil, err
	}

	keyClient := keyvault.New()
	keyClient.Authorizer = authorizer

	return &keyClient, nil
}

// func decodePem(certInput string) tls.Certificate {
// 	var cert tls.Certificate
// 	certPEMBlock := []byte(certInput)
// 	var certDERBlock *pem.Block
// 	for {
// 		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
// 		if certDERBlock == nil {
// 			break
// 		}
// 		if certDERBlock.Type == "CERTIFICATE" {
// 			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
// 		}
// 	}
// 	return cert
// }

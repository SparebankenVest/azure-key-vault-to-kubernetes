package main

import (
	"fmt"

	"github.com/Azure/go-autorest/autorest/azure/auth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CredentialsType contains the credentials type for authentication
type CredentialsType string

const (
	// CredentialsTypeClusterCredentials represent Azure AKS cluster credentials
	CredentialsTypeClusterCredentials CredentialsType = "clusterCredentials"

	// CredentialsTypeClientCredentials represent Azure Client Credentials
	CredentialsTypeClientCredentials CredentialsType = "clientCredentials"

	// CredentialsTypeClientCertificate represent Azure Certificate Credentials
	CredentialsTypeClientCertificate CredentialsType = "clientCertficate"

	// CredentialsTypeClientUsernamePassword represent Azure Username Password Credentials
	CredentialsTypeClientUsernamePassword CredentialsType = "usernamePassword"

	// CredentialsTypeManagedIdentitiesForAzureResources represent Azure Managed Identities for Azure resources Credentials (formerly known as MSI)
	CredentialsTypeManagedIdentitiesForAzureResources CredentialsType = "managedIdentitiesForAzureResources"
)

// AzureKeyVaultCredentials convert Azure Key Vault credentials to Kubernetes Secret
type AzureKeyVaultCredentials struct {
	CredentialsType CredentialsType
	envSettings     *auth.EnvironmentSettings
}

// NewCredentials represents a set of Azure credentials
func NewCredentials() (*AzureKeyVaultCredentials, error) {
	credType, envSettings, err := getCredentialsType()
	if err != nil {
		return nil, err
	}

	return &AzureKeyVaultCredentials{
		CredentialsType: credType,
		envSettings:     envSettings,
	}, nil
}

// GetKubernetesSecret return Azure credentials as a Kubernetes Secret
func (c *AzureKeyVaultCredentials) GetKubernetesSecret(secretName string) (*corev1.Secret, error) {
	switch c.CredentialsType {
	case CredentialsTypeClientCredentials:
		creds, err := c.envSettings.GetClientCredentials()
		if err != nil {
			return nil, err
		}

		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
			StringData: map[string]string{
				"client-id":     creds.ClientID,
				"client-secret": creds.ClientSecret,
				"tenant-id":     creds.TenantID,
			},
		}, nil

	case CredentialsTypeClientCertificate:
		creds, err := c.envSettings.GetClientCertificate()
		if err != nil {
			return nil, err
		}

		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
			StringData: map[string]string{
				"client-id":            creds.ClientID,
				"client-cert-path":     creds.CertificatePath,
				"client-cert-password": creds.CertificatePassword,
				"tenant-id":            creds.TenantID,
			},
		}, nil

	case CredentialsTypeClientUsernamePassword:
		creds, err := c.envSettings.GetUsernamePassword()
		if err != nil {
			return nil, err
		}

		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
			StringData: map[string]string{
				"client-id": creds.ClientID,
				"username":  creds.Username,
				"password":  creds.Password,
				"tenant-id": creds.TenantID,
			},
		}, nil

	default:
		return nil, fmt.Errorf("failed to get azure credentials, credential type %s unknown", c.CredentialsType)
	}
}

// GetEnvVarFromSecret asldkjf
func (c *AzureKeyVaultCredentials) GetEnvVarFromSecret(secretName string) *[]corev1.EnvVar {
	switch c.CredentialsType {
	case CredentialsTypeClientCredentials:
		return &[]corev1.EnvVar{
			formatEnvVar("AZURE_TENANT_ID", secretName, "tenant-id"),
			formatEnvVar("AZURE_CLIENT_ID", secretName, "client-id"),
			formatEnvVar("AZURE_CLIENT_SECRET", secretName, "client-secret"),
		}

	case CredentialsTypeClientCertificate:
		return &[]corev1.EnvVar{
			formatEnvVar("AZURE_TENANT_ID", secretName, "tenant-id"),
			formatEnvVar("AZURE_CLIENT_ID", secretName, "client-id"),
			formatEnvVar("AZURE_CERTIFICATE_PATH", secretName, "client-cert-path"),
			formatEnvVar("AZURE_CERTIFICATE_PASSWORD", secretName, "client-cert-password"),
		}

	case CredentialsTypeClientUsernamePassword:
		return &[]corev1.EnvVar{
			formatEnvVar("AZURE_TENANT_ID", secretName, "tenant-id"),
			formatEnvVar("AZURE_CLIENT_ID", secretName, "client-id"),
			formatEnvVar("AZURE_USERNAME", secretName, "username"),
			formatEnvVar("AZURE_PASSWORD", secretName, "password"),
		}

	default:
		envVars := make([]corev1.EnvVar, 0)
		return &envVars
	}
}

func formatEnvVar(envVarName, secretName, secretKey string) corev1.EnvVar {
	return corev1.EnvVar{
		Name: envVarName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretName,
				},
				Key: secretKey,
			},
		},
	}
}

func getCredentialsType() (CredentialsType, *auth.EnvironmentSettings, error) {
	envSettings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return "", nil, fmt.Errorf("failed to automatically detect azure keyvault credentials, error: %+v", err)
	}

	//1.Client Credentials
	if _, e := envSettings.GetClientCredentials(); e == nil {
		return CredentialsTypeClientCredentials, &envSettings, nil
	}

	//2. Client Certificate
	if _, e := envSettings.GetClientCertificate(); e == nil {
		return CredentialsTypeClientCertificate, &envSettings, nil
	}

	//3. Username Password
	if _, e := envSettings.GetUsernamePassword(); e == nil {
		return CredentialsTypeClientUsernamePassword, &envSettings, nil
	}

	// 4. MSI
	if _, e := envSettings.GetMSI().Authorizer(); e == nil {
		return CredentialsTypeManagedIdentitiesForAzureResources, &envSettings, nil
	}

	return "", nil, fmt.Errorf("failed to automatically detect azure keyvault credentials")
}

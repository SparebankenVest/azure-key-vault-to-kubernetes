package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/go-autorest/autorest/adal"
)

type LegacyTokenCredential interface {
	GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error)
}

func NewLegacyTokenCredentialAdal(token *adal.ServicePrincipalToken) LegacyTokenCredential {
	token.SetAutoRefresh(true)
	return &LegacyTokenCredentialAdal{token: token}
}

func NewLegacyTokenCredentialOauth(token string) LegacyTokenCredential {
	return &LegacyTokenCredentialOauth{token: token}
}

type LegacyTokenCredentialAdal struct {
	token *adal.ServicePrincipalToken
}

type LegacyTokenCredentialOauth struct {
	token string
}

func (m *LegacyTokenCredentialAdal) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if err := m.token.EnsureFresh(); err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{Token: m.token.Token().AccessToken, ExpiresOn: m.token.Token().Expires()}, nil
}

func (m *LegacyTokenCredentialOauth) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: m.token}, nil
}

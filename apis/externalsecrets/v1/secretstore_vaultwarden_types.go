/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// VaultwardenProvider configures a store to sync secrets with a self-hosted Vaultwarden instance.
type VaultwardenProvider struct {
	// URL is the base URL of the Vaultwarden instance, e.g. https://vault.example.com.
	// Only https:// URLs are accepted (enforced by the webhook and the provider).
	URL string `json:"url"`
	// Auth configures how ESO authenticates with Vaultwarden using a personal API key.
	Auth VaultwardenAuth `json:"auth"`
	// OrganizationID, if set, scopes this store to a single Vaultwarden
	// organization by UUID. Mutually exclusive with OrganizationName.
	// This is the recommended way to select an organization in production.
	// When both OrganizationID and OrganizationName are empty, the store
	// operates on the user's personal vault only.
	// +optional
	// +kubebuilder:validation:Format:=uuid
	OrganizationID string `json:"organizationId,omitempty"`
	// OrganizationName, if set, scopes this store to a single Vaultwarden
	// organization by its display name. The provider resolves the name to a
	// UUID from the authenticated user's profile when it authenticates.
	// Mutually exclusive with OrganizationID. Resolution fails if zero or
	// more than one of the user's organizations match the name.
	//
	// Prefer OrganizationID for production stores: a display name can be
	// renamed or duplicated by an organization admin, which silently changes
	// or breaks the store's scope. The webhook warns when this field is used.
	// +optional
	// +kubebuilder:validation:MinLength:=1
	OrganizationName string `json:"organizationName,omitempty"`
	// OrganizationKeyFingerprint pins the organization's symmetric key: the
	// lowercase or uppercase hex SHA-256 of the 64-byte unwrapped organization
	// key. The organization key reaches the provider wrapped with the user's
	// RSA public key, so a malicious or compromised server can substitute a
	// key it knows; when this field is set, the provider refuses to read or
	// write organization items unless the unwrapped key matches.
	// Only meaningful together with OrganizationID or OrganizationName.
	//
	// Obtain it once, from a trusted network path, with:
	//
	//	VW_URL=https://vault.example.com VW_CLIENT_ID=user.xxx VW_CLIENT_SECRET=... \
	//	VW_MASTER_PASSWORD=... VW_ORGANIZATION_ID=<uuid> \
	//	go run -tags vaultwarden ./providers/v1/vaultwarden/cmd/vw-org-fingerprint
	//
	// and re-pin it if the organization key is ever rotated.
	// +optional
	// +kubebuilder:validation:Pattern:=`^[0-9a-fA-F]{64}$`
	OrganizationKeyFingerprint string `json:"organizationKeyFingerprint,omitempty"`
	// CABundle is a base64-encoded PEM CA bundle used to validate the Vaultwarden server certificate.
	// If omitted, the system CA pool is used.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`
	// CAProvider references a Secret or ConfigMap key that holds a PEM CA bundle.
	// Takes precedence over CABundle when both are set.
	// +optional
	CAProvider *CAProvider `json:"caProvider,omitempty"`
}

// VaultwardenAuth holds references to the Kubernetes secrets containing Vaultwarden credentials.
type VaultwardenAuth struct {
	SecretRef VaultwardenSecretRef `json:"secretRef"`
}

// VaultwardenSecretRef contains selectors for the three credentials needed to access Vaultwarden.
type VaultwardenSecretRef struct {
	// ClientID is the OAuth2 client_id of the Vaultwarden personal API key.
	ClientID esmeta.SecretKeySelector `json:"clientID"`
	// ClientSecret is the OAuth2 client_secret of the Vaultwarden personal API key.
	ClientSecret esmeta.SecretKeySelector `json:"clientSecret"`
	// MasterPassword is the Vaultwarden account master password used to decrypt vault items.
	MasterPassword esmeta.SecretKeySelector `json:"masterPassword"`
}

//go:build vaultwarden || all_providers

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

package vaultwarden

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
)

// vaultwardenTokenResponse is the JSON response from /identity/connect/token.
type vaultwardenTokenResponse struct {
	AccessToken    string `json:"access_token"`
	Key            string `json:"Key"`   // encrypted symmetric key
	Kdf            int    `json:"Kdf"`
	KdfIterations  int    `json:"KdfIterations"`
	KdfMemory      *int   `json:"KdfMemory"`
	KdfParallelism *int   `json:"KdfParallelism"`
}

// vaultwardenProfile is the JSON response from /api/accounts/profile.
type vaultwardenProfile struct {
	Email          string `json:"email"`          // lowercase in profile response
	Key            string `json:"key"`            // lowercase
	Kdf            int    `json:"kdf"`
	KdfIterations  int    `json:"kdfIterations"`
	KdfMemory      *int   `json:"kdfMemory"`
	KdfParallelism *int   `json:"kdfParallelism"`

	// Organizations the user belongs to, each with its member-wrapped org key.
	Organizations []orgEntry `json:"organizations"`
	// PrivateKey is the user's RSA private key (PKCS#8 DER), encrypted with the
	// user's symmetric key (EncString type 2). Only needed for org-scoped stores.
	PrivateKey string `json:"privateKey"`
}

// orgEntry is one organization membership from /api/accounts/profile.
type orgEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Key is the 64-byte org symmetric key wrapped with the user's RSA public
	// key (EncString type 4, RSA-OAEP-SHA1).
	Key string `json:"key"`
}

// resolveOrgByName returns the UUID and wrapped key of the single organization
// whose name exactly matches name. It errors if zero or more than one match.
func resolveOrgByName(profile *vaultwardenProfile, name string) (orgID, encKey string, err error) {
	matches := 0
	for _, o := range profile.Organizations {
		if o.Name == name {
			orgID, encKey = o.ID, o.Key
			matches++
		}
	}
	switch matches {
	case 0:
		return "", "", fmt.Errorf("vaultwarden: no organization named %q", name)
	case 1:
		return orgID, encKey, nil
	default:
		return "", "", fmt.Errorf("vaultwarden: %d organizations are named %q; use organizationId instead", matches, name)
	}
}

// resolveOrgByID returns the wrapped key of the organization with the given UUID.
func resolveOrgByID(profile *vaultwardenProfile, id string) (string, error) {
	for _, o := range profile.Organizations {
		if strings.EqualFold(o.ID, id) {
			return o.Key, nil
		}
	}
	return "", fmt.Errorf("vaultwarden: organizationId %q not found among the user's organizations", id)
}

func (c *Client) resolveSecretKeyRef(ctx context.Context, sel esmeta.SecretKeySelector) (string, error) {
	storeKind := c.store.GetObjectKind().GroupVersionKind().Kind
	return resolvers.SecretKeyRef(ctx, c.crClient, storeKind, c.namespace, &sel)
}

// credentials are the three values a store needs to unlock a vault.
type credentials struct {
	clientID       string
	clientSecret   string
	masterPassword string
}

// resolveCredentials reads the store's API key and master password from Kubernetes.
func (c *Client) resolveCredentials(ctx context.Context) (*credentials, error) {
	secretRef := c.provider.Auth.SecretRef
	clientID, err := c.resolveSecretKeyRef(ctx, secretRef.ClientID)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: reading clientID: %w", err)
	}
	clientSecret, err := c.resolveSecretKeyRef(ctx, secretRef.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: reading clientSecret: %w", err)
	}
	masterPassword, err := c.resolveSecretKeyRef(ctx, secretRef.MasterPassword)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: reading masterPassword: %w", err)
	}
	return &credentials{clientID: clientID, clientSecret: clientSecret, masterPassword: masterPassword}, nil
}

// fetchToken authenticates via OAuth2 client credentials.
// Bitwarden/Vaultwarden identity API: POST /identity/connect/token
// https://bitwarden.com/help/public-api/#authentication
func (c *Client) fetchToken(ctx context.Context, creds *credentials) (*vaultwardenTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", creds.clientID)
	form.Set("client_secret", creds.clientSecret)
	form.Set("scope", "api")
	form.Set("DeviceIdentifier", uuid.NewSHA1(uuid.NameSpaceURL, []byte(c.namespace+"/"+c.store.GetName())).String())
	form.Set("DeviceType", "21")
	form.Set("DeviceName", "eso-provider")

	tokenURL := strings.TrimRight(c.provider.URL, "/") + "/identity/connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vaultwarden: token endpoint returned HTTP %d", resp.StatusCode)
	}

	var tokenResp vaultwardenTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("vaultwarden: decoding token response: %w", err)
	}
	return &tokenResp, nil
}

// fetchProfile fetches the account profile to read the encrypted symmetric key and KDF params.
// Bitwarden/Vaultwarden accounts API: GET /api/accounts/profile
// https://bitwarden.com/help/public-api/
func (c *Client) fetchProfile(ctx context.Context, accessToken string) (*vaultwardenProfile, error) {
	profileURL := strings.TrimRight(c.provider.URL, "/") + "/api/accounts/profile"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: building profile request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: profile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vaultwarden: profile endpoint returned HTTP %d", resp.StatusCode)
	}

	var profile vaultwardenProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("vaultwarden: decoding profile response: %w", err)
	}
	return &profile, nil
}

// getToken returns a cached or freshly derived access token and key material.
// Expensive HTTP calls and key derivation happen outside the mutex lock.
// The returned *cachedToken must be treated as read-only.
func (c *Client) getToken(ctx context.Context) (*cachedToken, error) {
	c.mu.Lock()
	if c.cache != nil && time.Now().Before(c.cache.expiresAt) {
		t := c.cache
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()

	creds, err := c.resolveCredentials(ctx)
	if err != nil {
		return nil, err
	}
	t, err := c.authenticate(ctx, creds)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache = t
	c.mu.Unlock()
	return t, nil
}

// authenticate logs in with creds, unlocks the user key and, for org-scoped
// stores, the organization key.
func (c *Client) authenticate(ctx context.Context, creds *credentials) (*cachedToken, error) {
	tokenResp, err := c.fetchToken(ctx, creds)
	if err != nil {
		return nil, err
	}
	profile, err := c.fetchProfile(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}

	memVal, parVal := 0, 0
	if profile.KdfMemory != nil {
		memVal = *profile.KdfMemory
	}
	if profile.KdfParallelism != nil {
		parVal = *profile.KdfParallelism
	}

	masterKey, err := crypto.DeriveKey(creds.masterPassword, profile.Email, profile.Kdf, profile.KdfIterations, memVal, parVal)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: deriving master key: %w", err)
	}

	stretchedEnc, stretchedMac, err := crypto.StretchKey(masterKey)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: stretching master key: %w", err)
	}

	profileKeyES, err := crypto.ParseEncString(profile.Key)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: parsing profile key: %w", err)
	}
	symKeyBytes, err := crypto.Decrypt(profileKeyES, stretchedEnc, stretchedMac)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: decrypting symmetric key: %w", err)
	}
	if len(symKeyBytes) < 64 {
		return nil, fmt.Errorf("vaultwarden: symmetric key too short (%d bytes)", len(symKeyBytes))
	}

	t := &cachedToken{
		accessToken: tokenResp.AccessToken,
		symEncKey:   symKeyBytes[0:32],
		symMacKey:   symKeyBytes[32:64],
		expiresAt:   time.Now().Add(5 * time.Minute),
	}
	if err := c.unlockOrgScope(profile, t); err != nil {
		t.invalidate()
		return nil, err
	}
	return t, nil
}

// unlockOrgScope populates t's org fields when the store is scoped to an
// organization (organizationId or organizationName). For personal scope it is
// a no-op. The org key is unwrapped with the user's RSA private key, which is
// itself encrypted with the user symmetric key (not the stretched master key).
func (c *Client) unlockOrgScope(profile *vaultwardenProfile, t *cachedToken) error {
	var orgID, wrappedKey string
	var err error
	switch {
	case c.provider.OrganizationID != "":
		orgID = c.provider.OrganizationID
		wrappedKey, err = resolveOrgByID(profile, orgID)
	case c.provider.OrganizationName != "":
		orgID, wrappedKey, err = resolveOrgByName(profile, c.provider.OrganizationName)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if wrappedKey == "" {
		return fmt.Errorf("vaultwarden: organization %q has no key for this user", orgID)
	}
	if profile.PrivateKey == "" {
		return errors.New("vaultwarden: user profile has no private key; cannot unlock organization key")
	}

	privDER, err := crypto.DecryptStringBytes(profile.PrivateKey, t.symEncKey, t.symMacKey)
	if err != nil {
		return fmt.Errorf("vaultwarden: decrypting user private key: %w", err)
	}
	rsaPriv, err := crypto.RSAPrivateKeyFromPKCS8DER(privDER)
	zeroBytes(privDER)
	if err != nil {
		return fmt.Errorf("vaultwarden: %w", err)
	}
	orgEnc, orgMac, fingerprint, err := unlockOrgKey(wrappedKey, rsaPriv)
	if err != nil {
		return err
	}
	if err := verifyOrgKeyFingerprint(c.provider.OrganizationKeyFingerprint, fingerprint); err != nil {
		zeroBytes(orgEnc)
		zeroBytes(orgMac)
		return err
	}
	t.orgID = orgID
	t.orgEncKey = orgEnc
	t.orgMacKey = orgMac
	t.orgKeyFingerprint = fingerprint
	return nil
}

// unlockOrgKey unwraps a type-4 org key with the user's RSA private key and
// splits the 64-byte plaintext into enc and mac keys. It also returns the
// SHA-256 fingerprint of the 64-byte key. The intermediate plaintext is zeroed
// before returning.
func unlockOrgKey(wrappedKey string, priv *rsa.PrivateKey) (orgEnc, orgMac []byte, fingerprint [sha256.Size]byte, err error) {
	plain, err := crypto.DecryptRSAOAEP(wrappedKey, priv)
	if err != nil {
		return nil, nil, fingerprint, fmt.Errorf("vaultwarden: unwrapping organization key: %w", err)
	}
	defer zeroBytes(plain)
	if len(plain) != 64 {
		return nil, nil, fingerprint, fmt.Errorf("vaultwarden: organization key has unexpected length %d", len(plain))
	}
	fingerprint = sha256.Sum256(plain)
	orgEnc = make([]byte, 32)
	orgMac = make([]byte, 32)
	copy(orgEnc, plain[:32])
	copy(orgMac, plain[32:])
	return orgEnc, orgMac, fingerprint, nil
}

// verifyOrgKeyFingerprint fails closed when the store pins an organization key
// fingerprint (hex SHA-256 of the 64-byte org key) and the unwrapped key does
// not match it. The org key is delivered RSA-wrapped to the user's public key,
// which the server knows, so without a pin a hostile server can substitute a
// key of its choosing. An empty pin disables the check.
func verifyOrgKeyFingerprint(pinned string, got [sha256.Size]byte) error {
	if pinned == "" {
		return nil
	}
	want, err := hex.DecodeString(strings.TrimSpace(pinned))
	if err != nil || len(want) != sha256.Size {
		return errors.New("vaultwarden: organizationKeyFingerprint must be 64 hex characters (SHA-256)")
	}
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return errors.New("vaultwarden: organization key does not match organizationKeyFingerprint; " +
			"refusing to use it (the server may have substituted the key, or the organization key was rotated)")
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// getProvider extracts the VaultwardenProvider config from a generic store.
func getProvider(store esv1.GenericStore) (*esv1.VaultwardenProvider, error) {
	spc := store.GetSpec()
	if spc == nil || spc.Provider == nil || spc.Provider.Vaultwarden == nil {
		return nil, fmt.Errorf(errUnexpectedStoreSpec)
	}
	return spc.Provider.Vaultwarden, nil
}


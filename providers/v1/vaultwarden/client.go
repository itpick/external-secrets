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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

// vaultwardenCipher represents a vault item returned from /api/sync.
type vaultwardenCipher struct {
	ID          string        `json:"id"`
	Type        int           `json:"type"`        // 1=Login, 2=SecureNote
	Name        string        `json:"name"`        // EncString
	Notes       string        `json:"notes"`       // EncString (may be empty)
	Login       *cipherLogin  `json:"login"`
	Fields      []cipherField `json:"fields"`
	DeletedDate any           `json:"deletedDate"`
	// OrganizationID is null for personal items and the org UUID otherwise.
	OrganizationID *string `json:"organizationId"`
}

type cipherLogin struct {
	Password string `json:"password"` // EncString
	Username string `json:"username"` // EncString
}

type cipherField struct {
	Name  string `json:"name"`  // EncString
	Value string `json:"value"` // EncString
	Type  int    `json:"type"`  // 0=text
}

// syncResponse is the subset of GET /api/sync the provider needs.
type syncResponse struct {
	Ciphers []vaultwardenCipher `json:"ciphers"`
}

const (
	cipherTypeLogin      = 1
	cipherTypeSecureNote = 2
)

// cipherOrgID returns the cipher's organization UUID, or "" for personal items.
func cipherOrgID(c *vaultwardenCipher) string {
	if c.OrganizationID == nil {
		return ""
	}
	return *c.OrganizationID
}

// filterCiphersByScope keeps the non-deleted Login and SecureNote ciphers that
// belong to the configured scope: orgID == "" keeps personal items only,
// otherwise only items owned by that organization are kept.
func filterCiphersByScope(ciphers []vaultwardenCipher, orgID string) []vaultwardenCipher {
	out := make([]vaultwardenCipher, 0, len(ciphers))
	for i := range ciphers {
		c := &ciphers[i]
		if c.DeletedDate != nil {
			continue
		}
		if c.Type != cipherTypeLogin && c.Type != cipherTypeSecureNote {
			continue
		}
		if !strings.EqualFold(cipherOrgID(c), orgID) {
			continue
		}
		out = append(out, *c)
	}
	return out
}

// cipherCreateBody is the JSON body for POST /api/ciphers and PUT /api/ciphers/{id}.
type cipherCreateBody struct {
	Type           int            `json:"type"`
	Name           string         `json:"name"`
	Notes          string         `json:"notes"`
	SecureNote     *secureNoteObj `json:"secureNote,omitempty"`
	FolderID       any            `json:"folderId"`
	OrganizationID any            `json:"organizationId"`
}

type secureNoteObj struct {
	Type int `json:"type"` // 0
}

// cachedToken holds a short-lived access token and symmetric key material
// so we don't re-authenticate on every API call within the same reconciliation.
type cachedToken struct {
	accessToken string
	symEncKey   []byte
	symMacKey   []byte
	expiresAt   time.Time

	// Org scope, populated only when the store sets organizationId or
	// organizationName. orgID is the resolved organization UUID.
	orgID     string
	orgEncKey []byte
	orgMacKey []byte
}

// keysFor returns the key pair that decrypts c: the org keys for a cipher owned
// by the scoped organization, the user's personal keys otherwise.
func (t *cachedToken) keysFor(c *vaultwardenCipher) (enc, mac []byte) {
	if t.orgID != "" && strings.EqualFold(cipherOrgID(c), t.orgID) {
		return t.orgEncKey, t.orgMacKey
	}
	return t.symEncKey, t.symMacKey
}

// invalidate zeroes all key material in place and clears the token so the
// secrets do not linger in memory once the client is done with them.
func (t *cachedToken) invalidate() {
	zeroBytes(t.symEncKey)
	zeroBytes(t.symMacKey)
	zeroBytes(t.orgEncKey)
	zeroBytes(t.orgMacKey)
	t.accessToken = ""
	t.symEncKey, t.symMacKey = nil, nil
	t.orgEncKey, t.orgMacKey = nil, nil
	t.orgID = ""
	t.expiresAt = time.Time{}
}

// writeKeys returns the key pair used to encrypt new ciphers in the store's scope.
func (t *cachedToken) writeKeys() (enc, mac []byte) {
	if t.orgID != "" {
		return t.orgEncKey, t.orgMacKey
	}
	return t.symEncKey, t.symMacKey
}

// Client implements esv1.SecretsClient for Vaultwarden.
type Client struct {
	httpClient *http.Client
	provider   *esv1.VaultwardenProvider
	crClient   client.Client
	namespace  string
	store      esv1.GenericStore

	mu    sync.Mutex
	cache *cachedToken
}

var _ esv1.SecretsClient = &Client{}

const bearerPrefix = "Bearer "

// pushMergePolicy controls what happens when PushSecret targets a cipher that already exists.
type pushMergePolicy string

const (
	// mergePolicyReplace overwrites the existing cipher (default).
	mergePolicyReplace pushMergePolicy = "Replace"
	// mergePolicyError returns an error if the cipher already exists.
	mergePolicyError pushMergePolicy = "Error"
)

// pushSecretMetadata is parsed from PushSecretData.GetMetadata().
type pushSecretMetadata struct {
	MergePolicy pushMergePolicy `json:"mergePolicy,omitempty"`
}

// Close zeroes the cached key material. The client re-authenticates if it is used again.
func (c *Client) Close(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache != nil {
		c.cache.invalidate()
		c.cache = nil
	}
	return nil
}

// Validate returns Unknown for ClusterSecretStore; otherwise authenticates and lists ciphers.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	if c.store.GetObjectKind().GroupVersionKind().Kind == esv1.ClusterSecretStoreKind {
		return esv1.ValidationResultUnknown, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tok, err := c.getToken(ctx)
	if err != nil {
		return esv1.ValidationResultError, fmt.Errorf("vaultwarden: validate: %w", err)
	}
	if _, err := c.listCiphers(ctx, tok); err != nil {
		return esv1.ValidationResultError, fmt.Errorf("vaultwarden: validate list: %w", err)
	}
	return esv1.ValidationResultReady, nil
}

// GetSecret returns a single secret value by cipher name (ref.Key).
// If ref.Property is set it looks up a named custom field; otherwise it returns
// the decrypted notes (SecureNote) or password (Login).
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	tok, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	ciphers, err := c.listCiphers(ctx, tok)
	if err != nil {
		return nil, err
	}
	cipher, err := findCipherByName(ciphers, ref.Key, tok)
	if err != nil {
		return nil, err
	}
	if ref.Property != "" {
		return getCipherProperty(cipher, ref.Property, tok)
	}
	return getCipherValue(cipher, ref.Key, tok)
}

// getCipherProperty looks up a named property from a cipher's custom fields,
// falling back to the cipher's Notes JSON for secrets written by this provider.
func getCipherProperty(cipher *vaultwardenCipher, property string, tok *cachedToken) ([]byte, error) {
	symEncKey, symMacKey := tok.keysFor(cipher)
	for _, f := range cipher.Fields {
		name, err := crypto.DecryptString(f.Name, symEncKey, symMacKey)
		if err != nil {
			continue
		}
		if name == property {
			val, err := crypto.DecryptString(f.Value, symEncKey, symMacKey)
			if err != nil {
				return nil, fmt.Errorf("vaultwarden: decrypting field value: %w", err)
			}
			return []byte(val), nil
		}
	}
	if v, err := getCipherPropertyFromNotes(cipher, property, symEncKey, symMacKey); err != nil {
		return nil, err
	} else if v != nil {
		return v, nil
	}
	return nil, fmt.Errorf("vaultwarden: field %q not found in secret %q", property, cipher.Name)
}

// getCipherPropertyFromNotes attempts to extract a property from the Notes JSON.
// Returns (nil, nil) when Notes is empty or not a JSON object (property not present).
func getCipherPropertyFromNotes(cipher *vaultwardenCipher, property string, symEncKey, symMacKey []byte) ([]byte, error) {
	if cipher.Notes == "" {
		return nil, nil
	}
	notes, err := crypto.DecryptString(cipher.Notes, symEncKey, symMacKey)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: decrypting notes: %w", err)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(notes), &obj) != nil {
		return nil, nil
	}
	if raw, ok := obj[property]; ok {
		return jsonRawToBytes(raw), nil
	}
	return nil, nil
}

// getCipherValue returns the primary value of a cipher:
// Notes for SecureNote (type 2), password for Login (type 1).
func getCipherValue(cipher *vaultwardenCipher, key string, tok *cachedToken) ([]byte, error) {
	symEncKey, symMacKey := tok.keysFor(cipher)
	if cipher.Type == 2 {
		val, err := crypto.DecryptString(cipher.Notes, symEncKey, symMacKey)
		if err != nil {
			return nil, fmt.Errorf("vaultwarden: decrypting notes: %w", err)
		}
		return []byte(val), nil
	}
	if cipher.Login != nil {
		val, err := crypto.DecryptString(cipher.Login.Password, symEncKey, symMacKey)
		if err != nil {
			return nil, fmt.Errorf("vaultwarden: decrypting password: %w", err)
		}
		return []byte(val), nil
	}
	return nil, fmt.Errorf("vaultwarden: secret %q has no usable value", key)
}

// GetSecretMap returns a map of keys to values by parsing the cipher's decrypted notes as JSON.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	tok, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	ciphers, err := c.listCiphers(ctx, tok)
	if err != nil {
		return nil, err
	}

	cipher, err := findCipherByName(ciphers, ref.Key, tok)
	if err != nil {
		return nil, err
	}

	if cipher.Notes == "" {
		return nil, fmt.Errorf("vaultwarden: secret %q has empty notes; cannot produce map", ref.Key)
	}

	encKey, macKey := tok.keysFor(cipher)
	notes, err := crypto.DecryptString(cipher.Notes, encKey, macKey)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: decrypting notes for map: %w", err)
	}

	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal([]byte(notes), &raw); err != nil {
		return nil, fmt.Errorf("vaultwarden: notes for %q are not a JSON object: %w", ref.Key, err)
	}

	out := make(map[string][]byte, len(raw))
	for k, v := range raw {
		out[k] = jsonRawToBytes(v)
	}
	return out, nil
}

// GetAllSecrets returns all ciphers (optionally filtered by name regexp) as a name→value map.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	tok, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	ciphers, err := c.listCiphers(ctx, tok)
	if err != nil {
		return nil, err
	}
	nameRe, err := compileNameRegexp(ref)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for i := range ciphers {
		name, val, ok := decryptCipherEntry(&ciphers[i], nameRe, tok)
		if ok {
			out[name] = val
		}
	}
	return out, nil
}

func compileNameRegexp(ref esv1.ExternalSecretFind) (*regexp.Regexp, error) {
	if ref.Name == nil || ref.Name.RegExp == "" {
		return nil, nil
	}
	re, err := regexp.Compile(ref.Name.RegExp)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: invalid name regexp %q: %w", ref.Name.RegExp, err)
	}
	return re, nil
}

// decryptCipherEntry returns (name, value, true) or ("", nil, false) if the entry should be skipped.
func decryptCipherEntry(cipher *vaultwardenCipher, nameRe *regexp.Regexp, tok *cachedToken) (string, []byte, bool) {
	symEncKey, symMacKey := tok.keysFor(cipher)
	if cipher.DeletedDate != nil {
		return "", nil, false
	}
	name, err := crypto.DecryptString(cipher.Name, symEncKey, symMacKey)
	if err != nil || (nameRe != nil && !nameRe.MatchString(name)) {
		return "", nil, false
	}
	val, err := decryptCipherPrimaryValue(cipher, symEncKey, symMacKey)
	if err != nil {
		return "", nil, false
	}
	return name, []byte(val), true
}

func decryptCipherPrimaryValue(cipher *vaultwardenCipher, symEncKey, symMacKey []byte) (string, error) {
	if cipher.Type == 2 {
		return crypto.DecryptString(cipher.Notes, symEncKey, symMacKey)
	}
	if cipher.Login != nil {
		return crypto.DecryptString(cipher.Login.Password, symEncKey, symMacKey)
	}
	return "", nil
}

// PushSecret writes a secret value to Vaultwarden as a SecureNote cipher.
// Accepts optional metadata: {"mergePolicy":"Replace"} (default) or {"mergePolicy":"Error"}.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	var meta pushSecretMetadata
	if m := data.GetMetadata(); m != nil {
		if err := json.Unmarshal(m.Raw, &meta); err != nil {
			return fmt.Errorf("vaultwarden: invalid push metadata: %w", err)
		}
	}
	if meta.MergePolicy == "" {
		meta.MergePolicy = mergePolicyReplace
	}

	tok, err := c.getToken(ctx)
	if err != nil {
		return err
	}
	value, err := buildPushValue(secret, data)
	if err != nil {
		return err
	}
	cipherName := data.GetRemoteKey()
	bodyBytes, err := buildCipherBody(cipherName, string(value), tok)
	if err != nil {
		return err
	}
	ciphers, err := c.listCiphers(ctx, tok)
	if err != nil {
		return err
	}
	existing := findCipherByNameNoErr(ciphers, cipherName, tok)
	if existing != nil && meta.MergePolicy == mergePolicyError {
		return fmt.Errorf("vaultwarden: cipher %q already exists and mergePolicy is Error", cipherName)
	}
	return c.upsertCipher(ctx, tok.accessToken, existing, bodyBytes)
}

// buildPushValue extracts the value to push from the Kubernetes secret.
// If a specific key is requested, that key's raw bytes are returned.
// Otherwise all data keys are JSON-marshalled as a string map.
func buildPushValue(secret *corev1.Secret, data esv1.PushSecretData) ([]byte, error) {
	if key := data.GetSecretKey(); key != "" {
		val, ok := secret.Data[key]
		if !ok {
			return nil, fmt.Errorf("vaultwarden: key %q not found in secret %s/%s", key, secret.Namespace, secret.Name)
		}
		return val, nil
	}
	// Convert []byte values to strings so json.Marshal does not base64-encode them,
	// preserving round-trip fidelity with GetSecretMap.
	strData := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		strData[k] = string(v)
	}
	b, err := json.Marshal(strData)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: marshalling secret data: %w", err)
	}
	return b, nil
}

// buildCipherBody encrypts a SecureNote for the store's scope. For org-scoped
// stores the cipher is encrypted with the org key and tagged with the org UUID.
func buildCipherBody(name, notes string, tok *cachedToken) ([]byte, error) {
	symEncKey, symMacKey := tok.writeKeys()
	encName, err := crypto.EncryptString(name, symEncKey, symMacKey)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: encrypting cipher name: %w", err)
	}
	encNotes, err := crypto.EncryptString(notes, symEncKey, symMacKey)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: encrypting cipher notes: %w", err)
	}
	body := cipherCreateBody{
		Type:       cipherTypeSecureNote,
		Name:       encName,
		Notes:      encNotes,
		SecureNote: &secureNoteObj{Type: 0},
	}
	if tok.orgID != "" {
		body.OrganizationID = tok.orgID
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: marshalling cipher body: %w", err)
	}
	return b, nil
}

// upsertCipher sends a PUT (update) or POST (create) request depending on whether existing is set.
// API reference: https://bitwarden.com/help/vault-management-api/ and https://github.com/dani-garcia/vaultwarden/wiki
func (c *Client) upsertCipher(ctx context.Context, accessToken string, existing *vaultwardenCipher, bodyBytes []byte) error {
	base := strings.TrimRight(c.provider.URL, "/")
	var method, url string
	if existing != nil {
		method = http.MethodPut
		url = fmt.Sprintf("%s/api/ciphers/%s", base, existing.ID)
	} else {
		method = http.MethodPost
		url = base + "/api/ciphers"
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("vaultwarden: building cipher request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearerPrefix+accessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vaultwarden: cipher request failed: %w", err)
	}
	defer resp.Body.Close()
	// The response body is deliberately not included: it may echo request content.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vaultwarden: cipher request returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// DeleteSecret deletes the cipher matching the remote ref's key. Idempotent — returns nil if not found.
func (c *Client) DeleteSecret(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) error {
	tok, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	ciphers, err := c.listCiphers(ctx, tok)
	if err != nil {
		return err
	}

	cipher := findCipherByNameNoErr(ciphers, remoteRef.GetRemoteKey(), tok)
	if cipher == nil {
		return nil
	}

	base := strings.TrimRight(c.provider.URL, "/")
	deleteURL := fmt.Sprintf("%s/api/ciphers/%s", base, cipher.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteURL, nil)
	if err != nil {
		return fmt.Errorf("vaultwarden: building delete request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+tok.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vaultwarden: deleting cipher: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("vaultwarden: delete cipher returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// SecretExists returns true if a cipher with the given remote key name exists in the vault.
func (c *Client) SecretExists(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) (bool, error) {
	tok, err := c.getToken(ctx)
	if err != nil {
		return false, err
	}

	ciphers, err := c.listCiphers(ctx, tok)
	if err != nil {
		return false, err
	}

	cipher := findCipherByNameNoErr(ciphers, remoteRef.GetRemoteKey(), tok)
	return cipher != nil, nil
}

// listCiphers fetches the vault via /api/sync (which, unlike /api/ciphers, is
// guaranteed to include organization items the user can access) and returns
// only the ciphers in the store's scope.
func (c *Client) listCiphers(ctx context.Context, tok *cachedToken) ([]vaultwardenCipher, error) {
	syncURL := strings.TrimRight(c.provider.URL, "/") + "/api/sync?excludeDomains=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, syncURL, nil)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: building sync request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+tok.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: sync request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vaultwarden: sync endpoint returned HTTP %d", resp.StatusCode)
	}

	var sync syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&sync); err != nil {
		return nil, fmt.Errorf("vaultwarden: decoding sync response: %w", err)
	}
	return filterCiphersByScope(sync.Ciphers, tok.orgID), nil
}

// findCipherByName returns the matching cipher or esv1.NoSecretError.
// Returns an error if not found.
func findCipherByName(ciphers []vaultwardenCipher, target string, tok *cachedToken) (*vaultwardenCipher, error) {
	c := findCipherByNameNoErr(ciphers, target, tok)
	if c == nil {
		return nil, fmt.Errorf("vaultwarden: secret %q not found", target)
	}
	return c, nil
}

// findCipherByNameNoErr is like findCipherByName but returns nil instead of an error.
func findCipherByNameNoErr(ciphers []vaultwardenCipher, target string, tok *cachedToken) *vaultwardenCipher {
	for i := range ciphers {
		if ciphers[i].DeletedDate != nil {
			continue
		}
		encKey, macKey := tok.keysFor(&ciphers[i])
		name, err := crypto.DecryptString(ciphers[i].Name, encKey, macKey)
		if err != nil {
			continue
		}
		if name == target {
			return &ciphers[i]
		}
	}
	return nil
}

// jsonRawToBytes converts a json.RawMessage to []byte.
// For JSON strings the surrounding quotes are stripped; other types are returned as-is.
func jsonRawToBytes(raw json.RawMessage) []byte {
	if len(raw) > 1 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return []byte(s)
		}
	}
	return []byte(raw)
}

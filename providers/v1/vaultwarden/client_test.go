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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

func cipherIDs(cs []vaultwardenCipher) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func TestFilterCiphersByScope(t *testing.T) {
	ciphers := []vaultwardenCipher{
		{ID: "p1", Type: 1},
		{ID: "p2", Type: 2},
		{ID: "o1", Type: 1, OrganizationID: new("uuid-a")},
		{ID: "o2", Type: 2, OrganizationID: new("uuid-b")},
		{ID: "deleted", Type: 1, DeletedDate: "2026-01-01T00:00:00Z"},
		{ID: "card", Type: 3},
	}
	assert.Equal(t, []string{"p1", "p2"}, cipherIDs(filterCiphersByScope(ciphers, "")))
	assert.Equal(t, []string{"o1"}, cipherIDs(filterCiphersByScope(ciphers, "uuid-a")))
	assert.Equal(t, []string{"o1"}, cipherIDs(filterCiphersByScope(ciphers, "UUID-A")))
	assert.Empty(t, filterCiphersByScope(ciphers, "uuid-z"))
}

func TestKeysFor(t *testing.T) {
	tok := &cachedToken{
		symEncKey: make32(1), symMacKey: make32(33),
		orgID: "uuid-a", orgEncKey: make32(65), orgMacKey: make32(97),
	}
	enc, mac := tok.keysFor(&vaultwardenCipher{OrganizationID: new("uuid-a")})
	assert.Equal(t, tok.orgEncKey, enc)
	assert.Equal(t, tok.orgMacKey, mac)
	enc, _ = tok.keysFor(&vaultwardenCipher{})
	assert.Equal(t, tok.symEncKey, enc)
	enc, _ = tok.keysFor(&vaultwardenCipher{OrganizationID: new("uuid-b")})
	assert.Equal(t, tok.symEncKey, enc)
}

// fakeVaultwarden is a minimal in-memory Vaultwarden API: token, profile, sync, create/update.
type fakeVaultwarden struct {
	t       *testing.T
	profile map[string]any
	mu      sync.Mutex
	ciphers []map[string]any
	posted  []map[string]any
	paths   []string
}

func (f *fakeVaultwarden) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/identity/connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"})
	case r.Method == http.MethodGet && r.URL.Path == "/api/accounts/profile":
		_ = json.NewEncoder(w).Encode(f.profile)
	case r.Method == http.MethodGet && r.URL.Path == "/api/sync":
		_ = json.NewEncoder(w).Encode(map[string]any{"ciphers": f.ciphers})
	case r.Method == http.MethodPost && r.URL.Path == "/api/ciphers":
		var body map[string]any
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
		f.posted = append(f.posted, body)
		_, _ = w.Write([]byte("{}"))
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

type testPushData struct{ secretKey, remoteKey string }

func (d testPushData) GetMetadata() *apiextensionsv1.JSON { return nil }
func (d testPushData) GetSecretKey() string               { return d.secretKey }
func (d testPushData) GetRemoteKey() string               { return d.remoteKey }
func (d testPushData) GetProperty() string                { return "" }

const (
	testEmail    = "eso@example.com"
	testPassword = "correct horse battery staple"
)

// newFakeVaultwarden builds a server holding a personal and an org cipher with
// the same name, plus a Client pointed at it with the given scope.
func newFakeVaultwarden(t *testing.T, scope esv1.VaultwardenProvider) (*fakeVaultwarden, *Client) {
	t.Helper()
	userEnc, userMac := make32(1), make32(33)
	orgKey := append(make32(65), make32(97)...)

	masterKey, err := crypto.DeriveKey(testPassword, testEmail, crypto.KdfTypePBKDF2, 1, 0, 0)
	require.NoError(t, err)
	stretchedEnc, stretchedMac, err := crypto.StretchKey(masterKey)
	require.NoError(t, err)
	protectedUserKey, err := crypto.Encrypt(append(append([]byte{}, userEnc...), userMac...), stretchedEnc, stretchedMac)
	require.NoError(t, err)

	p := fakeOrgProfile(t, userEnc, userMac, orgKey, "Example")
	profile := map[string]any{
		"email": testEmail, "key": protectedUserKey, "kdf": 0, "kdfIterations": 1,
		"privateKey": p.PrivateKey, "organizations": p.Organizations,
	}

	enc := func(s string, e, m []byte) string {
		out, err := crypto.EncryptString(s, e, m)
		require.NoError(t, err)
		return out
	}
	ciphers := []map[string]any{
		{"id": "personal", "type": 2, "organizationId": nil, "deletedDate": nil,
			"name": enc("db-password", userEnc, userMac), "notes": enc("personal-value", userEnc, userMac)},
		{"id": "org", "type": 2, "organizationId": testOrgID, "deletedDate": nil,
			"name": enc("db-password", orgKey[:32], orgKey[32:]), "notes": enc("org-value", orgKey[:32], orgKey[32:])},
	}

	fv := &fakeVaultwarden{t: t, profile: profile, ciphers: ciphers}
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)

	creds := &corev1.Secret{
		Name: "vw", Namespace: "default",
		Data: map[string][]byte{
			"clientID": []byte("user.id"), "clientSecret": []byte("secret"), "masterPassword": []byte(testPassword),
		},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	kube := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(creds).Build()

	prov := scope
	prov.URL = srv.URL
	prov.Auth.SecretRef = esv1.VaultwardenSecretRef{
		ClientID:       esmeta.SecretKeySelector{Name: "vw", Key: "clientID"},
		ClientSecret:   esmeta.SecretKeySelector{Name: "vw", Key: "clientSecret"},
		MasterPassword: esmeta.SecretKeySelector{Name: "vw", Key: "masterPassword"},
	}
	store := &esv1.SecretStore{
		Kind: esv1.SecretStoreKind,
		Name: "vw-store", Namespace: "default",
		Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{Vaultwarden: &prov}},
	}
	return fv, &Client{httpClient: srv.Client(), provider: &prov, crClient: kube, namespace: "default", store: store}
}

func TestScopedGetSecret(t *testing.T) {
	cases := []struct {
		name  string
		scope esv1.VaultwardenProvider
		want  string
	}{
		{"personal", esv1.VaultwardenProvider{}, "personal-value"},
		{"org by id", esv1.VaultwardenProvider{OrganizationID: testOrgID}, "org-value"},
		{"org by name", esv1.VaultwardenProvider{OrganizationName: "Example"}, "org-value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv, c := newFakeVaultwarden(t, tc.scope)
			got, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))

			all, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
			require.NoError(t, err)
			assert.Equal(t, map[string][]byte{"db-password": []byte(tc.want)}, all)
			assert.Contains(t, fv.paths, "GET /api/sync")
		})
	}
}

func TestScopedPushSecretUsesOrgKey(t *testing.T) {
	fv, c := newFakeVaultwarden(t, esv1.VaultwardenProvider{OrganizationName: "Example"})
	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("pushed")}}
	require.NoError(t, c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "new-item"}))

	require.Len(t, fv.posted, 1)
	body := fv.posted[0]
	assert.Equal(t, testOrgID, body["organizationId"])

	tok, err := c.getToken(context.Background())
	require.NoError(t, err)
	name, err := crypto.DecryptString(body["name"].(string), tok.orgEncKey, tok.orgMacKey)
	require.NoError(t, err)
	assert.Equal(t, "new-item", name)
	notes, err := crypto.DecryptString(body["notes"].(string), tok.orgEncKey, tok.orgMacKey)
	require.NoError(t, err)
	assert.Equal(t, "pushed", notes)
}

func TestPersonalPushSecretHasNoOrg(t *testing.T) {
	fv, c := newFakeVaultwarden(t, esv1.VaultwardenProvider{})
	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("pushed")}}
	require.NoError(t, c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "new-item"}))
	require.Len(t, fv.posted, 1)
	assert.Nil(t, fv.posted[0]["organizationId"])
}

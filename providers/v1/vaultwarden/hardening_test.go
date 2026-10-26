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

// Regression tests for the security review of the Vaultwarden provider. Each
// test drives the provider against a hostile or misbehaving fake server.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

// hostileServer is a controllable fake Vaultwarden that records what it is sent.
type hostileServer struct {
	mu       sync.Mutex
	profile  map[string]any
	ciphers  []map[string]any
	reqs     []string
	posted   []map[string]any
	puts     map[string]map[string]any
	syncHook func(w http.ResponseWriter, r *http.Request) bool // returns true if it handled the request
}

func (f *hostileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.EscapedPath())
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/identity/connect/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 7200})
	case r.Method == http.MethodGet && r.URL.Path == "/api/accounts/profile":
		_ = json.NewEncoder(w).Encode(f.profile)
	case r.Method == http.MethodGet && r.URL.Path == "/api/sync":
		if f.syncHook != nil && f.syncHook(w, r) {
			return
		}
		f.mu.Lock()
		body := map[string]any{"ciphers": f.ciphers}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(body)
	case r.Method == http.MethodPost && r.URL.Path == "/api/ciphers":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.posted = append(f.posted, body)
		f.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/ciphers/"):
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		if f.puts == nil {
			f.puts = map[string]map[string]any{}
		}
		f.puts[strings.TrimPrefix(r.URL.EscapedPath(), "/api/ciphers/")] = body
		f.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/ciphers/"):
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *hostileServer) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *hostileServer) count(req string) int {
	n := 0
	for _, r := range f.requests() {
		if r == req {
			n++
		}
	}
	return n
}

// testKdfIterations is the smallest PBKDF2 iteration count the provider accepts.
const testKdfIterations = 100000

type hostileKeys struct {
	userEnc, userMac []byte
	orgKey           []byte
	priv             *rsa.PrivateKey
	protectedUserKey string
	encPriv          string
}

func newHostileKeys(t *testing.T) hostileKeys {
	t.Helper()
	k := hostileKeys{userEnc: make32(1), userMac: make32(33), orgKey: append(make32(65), make32(97)...)}
	masterKey, err := crypto.DeriveKey(context.Background(), testPassword, testEmail, crypto.KdfTypePBKDF2, testKdfIterations, 0, 0)
	require.NoError(t, err)
	se, sm, err := crypto.StretchKey(masterKey)
	require.NoError(t, err)
	k.protectedUserKey, err = crypto.Encrypt(append(append([]byte{}, k.userEnc...), k.userMac...), se, sm)
	require.NoError(t, err)
	k.priv, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	require.NoError(t, err)
	k.encPriv, err = crypto.Encrypt(der, k.userEnc, k.userMac)
	require.NoError(t, err)
	return k
}

// personalProfile is a profile with no organizations.
func (k hostileKeys) personalProfile() map[string]any {
	return map[string]any{"email": testEmail, "key": k.protectedUserKey, "kdf": 0, "kdfIterations": testKdfIterations}
}

// orgProfile is a profile with one organization whose wrapped key is orgKey.
func (k hostileKeys) orgProfile(t *testing.T, orgKey []byte) map[string]any {
	p := k.personalProfile()
	p["privateKey"] = k.encPriv
	p["organizations"] = []map[string]any{{"id": testOrgID, "name": "Example", "key": wrapOrgKey(t, &k.priv.PublicKey, orgKey)}}
	return p
}

func encS(t *testing.T, s string, e, m []byte) string {
	t.Helper()
	out, err := crypto.EncryptString(s, e, m)
	require.NoError(t, err)
	return out
}

func fingerprintOf(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func hostileCredsKube(t *testing.T) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		Name: "vw", Namespace: "default",
		Data: map[string][]byte{
			"clientID": []byte("user.id"), "clientSecret": []byte("SUPER-SECRET-CLIENT-SECRET"), "masterPassword": []byte(testPassword),
		},
	}
}

// newHostileClient returns a Client for a SecretStore pointed at srv with the given scope.
func newHostileClient(t *testing.T, srv *httptest.Server, scope esv1.VaultwardenProvider) *Client {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	kube := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(hostileCredsKube(t)).Build()
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
	return &Client{httpClient: srv.Client(), provider: &prov, crClient: kube, namespace: "default", store: store}
}

// H1: a server that substitutes the RSA-wrapped organization key with one it
// knows must be rejected when the store pins the organization key fingerprint,
// for reads and, crucially, before any PushSecret payload is encrypted.
func TestOrgKeyFingerprintRejectsSubstitutedKey(t *testing.T) {
	k := newHostileKeys(t)
	attackerKey := make([]byte, 64)
	_, _ = rand.Read(attackerKey)
	aEnc, aMac := attackerKey[:32], attackerKey[32:]

	fv := &hostileServer{
		profile: k.orgProfile(t, attackerKey),
		ciphers: []map[string]any{
			{"id": "org", "type": 2, "organizationId": testOrgID, "deletedDate": nil,
				"name": encS(t, "db-password", aEnc, aMac), "notes": encS(t, "INJECTED-BY-SERVER", aEnc, aMac)},
		},
	}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()

	c := newHostileClient(t, srv, esv1.VaultwardenProvider{
		OrganizationID:             testOrgID,
		OrganizationKeyFingerprint: fingerprintOf(k.orgKey),
	})
	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organizationKeyFingerprint")

	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("TOP-SECRET-PUSHED-VALUE")}}
	err = c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "new-item"})
	require.Error(t, err)
	assert.Empty(t, fv.posted, "nothing may be pushed under an unverified organization key")
}

// H1: the matching fingerprint (either hex case) is accepted.
func TestOrgKeyFingerprintAcceptsGenuineKey(t *testing.T) {
	k := newHostileKeys(t)
	fv := &hostileServer{
		profile: k.orgProfile(t, k.orgKey),
		ciphers: []map[string]any{
			{"id": "org", "type": 2, "organizationId": testOrgID, "deletedDate": nil,
				"name": encS(t, "db-password", k.orgKey[:32], k.orgKey[32:]), "notes": encS(t, "org-value", k.orgKey[:32], k.orgKey[32:])},
		},
	}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()

	for _, fp := range []string{fingerprintOf(k.orgKey), strings.ToUpper(fingerprintOf(k.orgKey))} {
		c := newHostileClient(t, srv, esv1.VaultwardenProvider{OrganizationName: "Example", OrganizationKeyFingerprint: fp})
		val, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
		require.NoError(t, err)
		assert.Equal(t, "org-value", string(val))
	}
}

// H1: an org-scoped store without a pinned fingerprint is admitted with a
// warning; a malformed or orphaned fingerprint is rejected.
func TestValidateStoreOrgKeyFingerprint(t *testing.T) {
	const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	p := &Provider{}
	w, err := p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationID: testOrgID}))
	require.NoError(t, err)
	assert.True(t, containsSubstring(w, "organizationKeyFingerprint"), "warnings: %v", w)

	w, err = p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationID: testOrgID, OrganizationKeyFingerprint: fp}))
	require.NoError(t, err)
	assert.False(t, containsSubstring(w, "organizationKeyFingerprint"), "warnings: %v", w)

	_, err = p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationID: testOrgID, OrganizationKeyFingerprint: "abc"}))
	require.Error(t, err)
	_, err = p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationKeyFingerprint: fp}))
	require.Error(t, err)
}

func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// H1: the operator helper reports the fingerprint of the genuine org key.
func TestOrganizationKeyFingerprintHelper(t *testing.T) {
	k := newHostileKeys(t)
	srv := httptest.NewTLSServer(&hostileServer{profile: k.orgProfile(t, k.orgKey)})
	defer srv.Close()
	got, err := OrganizationKeyFingerprint(context.Background(), srv.Client(), srv.URL, testOrgID, "user.id", "secret", testPassword)
	require.NoError(t, err)
	assert.Equal(t, fingerprintOf(k.orgKey), got)
}

// L1: a GetSecretMap parse failure must not echo plaintext bytes from the
// notes (encoding/json syntax errors quote the offending character).
func TestGetSecretMapErrorDoesNotLeakPlaintext(t *testing.T) {
	k := newHostileKeys(t)
	fv := &hostileServer{
		profile: k.personalProfile(),
		ciphers: []map[string]any{
			{"id": "p", "type": 2, "organizationId": nil, "deletedDate": nil,
				"name": encS(t, "api-token", k.userEnc, k.userMac), "notes": encS(t, "hunter2", k.userEnc, k.userMac)},
			{"id": "q", "type": 2, "organizationId": nil, "deletedDate": nil,
				"name": encS(t, "half-json", k.userEnc, k.userMac), "notes": encS(t, `{"user":"admin"} Zecret`, k.userEnc, k.userMac)},
		},
	}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})

	for key, leak := range map[string]string{"api-token": "'h'", "half-json": "'Z'"} {
		_, err := c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: key})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), leak)
		assert.Contains(t, err.Error(), key)
	}
}

// L2: the property-not-found error names the requested key, not the
// cipher's EncString.
func TestPropertyNotFoundErrorUsesKey(t *testing.T) {
	k := newHostileKeys(t)
	encName := encS(t, "svc", k.userEnc, k.userMac)
	fv := &hostileServer{
		profile: k.personalProfile(),
		ciphers: []map[string]any{{"id": "p", "type": 2, "organizationId": nil, "deletedDate": nil, "name": encName, "notes": ""}},
	}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "svc", Property: "nope"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), encName)
	assert.Contains(t, err.Error(), `"svc"`)
}

// L3: a differently-cased organizationId is canonicalised to the server's
// spelling before it is sent on writes.
func TestOrganizationIDCanonicalised(t *testing.T) {
	k := newHostileKeys(t)
	fv := &hostileServer{profile: k.orgProfile(t, k.orgKey)}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{OrganizationID: strings.ToUpper(testOrgID)})
	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	require.NoError(t, c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "x"}))
	require.Len(t, fv.posted, 1)
	assert.Equal(t, testOrgID, fv.posted[0]["organizationId"])
}

// M3: server-supplied PBKDF2 iteration counts outside the accepted range are
// rejected instead of burning unbounded controller CPU.
func TestKDFIterationsBounded(t *testing.T) {
	k := newHostileKeys(t)
	for _, iters := range []int{1, 99999, 2000001, 5000000} {
		profile := k.personalProfile()
		profile["kdfIterations"] = iters
		srv := httptest.NewTLSServer(&hostileServer{profile: profile})
		c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
		start := time.Now()
		_, err := c.getToken(context.Background())
		el := time.Since(start)
		srv.Close()
		require.Error(t, err, "kdfIterations=%d", iters)
		assert.Contains(t, err.Error(), "kdfIterations")
		assert.Less(t, el, time.Second, "kdfIterations=%d", iters)
	}
}

// M3: key derivation is abandoned when the context is cancelled.
func TestKDFHonoursContextCancellation(t *testing.T) {
	k := newHostileKeys(t)
	profile := k.personalProfile()
	profile["kdfIterations"] = 2000000

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fv := &hostileServer{profile: profile}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fv.ServeHTTP(w, r)
		if r.URL.Path == "/api/accounts/profile" {
			// Cancel once the client has the profile and is deriving the key.
			time.AfterFunc(20*time.Millisecond, cancel)
		}
	}))
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	_, err := c.getToken(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// M2: an oversized /api/sync body is rejected rather than decoded into
// unbounded controller memory.
func TestSyncBodySizeLimited(t *testing.T) {
	k := newHostileKeys(t)
	filler := strings.Repeat("A", 16*1024)
	fv := &hostileServer{profile: k.personalProfile()}
	fv.syncHook = func(w http.ResponseWriter, _ *http.Request) bool {
		_, _ = w.Write([]byte(`{"ciphers":[`))
		for i := 0; i < 4200; i++ { // ~68 MiB
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			_, _ = fmt.Fprintf(w, `{"id":"%d","type":2,"organizationId":null,"deletedDate":null,"name":"2.x|y|z","notes":"%s"}`, i, filler)
		}
		_, _ = w.Write([]byte(`]}`))
		return true
	}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	_, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size limit")
}

// M2: oversized token and profile bodies are rejected.
func TestAuthBodySizeLimited(t *testing.T) {
	k := newHostileKeys(t)
	pad := strings.Repeat("A", 2<<20)
	for _, path := range []string{"/identity/connect/token", "/api/accounts/profile"} {
		t.Run(path, func(t *testing.T) {
			profile := k.personalProfile()
			fv := &hostileServer{profile: profile}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == path {
					w.Header().Set("Content-Type", "application/json")
					if path == "/api/accounts/profile" {
						profile["padding"] = pad
						_ = json.NewEncoder(w).Encode(profile)
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "padding": pad})
					}
					return
				}
				fv.ServeHTTP(w, r)
			}))
			defer srv.Close()
			c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
			_, err := c.getToken(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "size limit")
		})
	}
}

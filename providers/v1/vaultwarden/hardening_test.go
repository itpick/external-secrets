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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

// testMasterKey derives the test account's master key once per test binary
// (PBKDF2 at the minimum accepted iteration count is slow under -race).
var testMasterKey = sync.OnceValues(func() ([]byte, error) {
	return crypto.DeriveKey(context.Background(), testPassword, testEmail, crypto.KdfTypePBKDF2, testKdfIterations, 0, 0)
})

// testStretchedKeys returns the stretched enc/mac keys of the test account.
func testStretchedKeys(t *testing.T) (enc, mac []byte) {
	t.Helper()
	masterKey, err := testMasterKey()
	require.NoError(t, err)
	enc, mac, err = crypto.StretchKey(masterKey)
	require.NoError(t, err)
	return enc, mac
}

func newHostileKeys(t *testing.T) hostileKeys {
	t.Helper()
	k := hostileKeys{userEnc: make32(1), userMac: make32(33), orgKey: append(make32(65), make32(97)...)}
	se, sm := testStretchedKeys(t)
	var err error
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// M3: key derivation is abandoned when the context is canceled.
func TestKDFHonoursContextCancellation(t *testing.T) {
	t.Parallel()
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
// unbounded controller memory. Not parallel: it lowers the package limit
// (decoding 64 MiB under -race takes minutes); the test streams ~4 MiB more
// than the limit.
func TestSyncBodySizeLimited(t *testing.T) {
	orig := maxSyncBodyBytes
	maxSyncBodyBytes = 4 << 20
	t.Cleanup(func() { maxSyncBodyBytes = orig })
	k := newHostileKeys(t)
	filler := strings.Repeat("A", 16*1024)
	fv := &hostileServer{profile: k.personalProfile()}
	n := int(maxSyncBodyBytes/int64(len(filler))) + 256
	fv.syncHook = func(w http.ResponseWriter, _ *http.Request) bool {
		_, _ = w.Write([]byte(`{"ciphers":[`))
		for i := range n {
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
	t.Parallel()
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

const testManagedField = "external-secrets.io/managed"

// managedNote returns a personal SecureNote cipher carrying the ESO marker field.
func managedNote(t *testing.T, k hostileKeys, id, name, notes string) map[string]any {
	return map[string]any{"id": id, "type": 2, "organizationId": nil, "deletedDate": nil,
		"name": encS(t, name, k.userEnc, k.userMac), "notes": encS(t, notes, k.userEnc, k.userMac),
		"fields": []map[string]any{{"name": encS(t, testManagedField, k.userEnc, k.userMac), "value": encS(t, "true", k.userEnc, k.userMac), "type": 0}}}
}

func hasManagedMarker(t *testing.T, body map[string]any, e, m []byte) bool {
	t.Helper()
	fields, _ := body["fields"].([]any)
	for _, f := range fields {
		fm, _ := f.(map[string]any)
		name, err1 := crypto.DecryptString(fmt.Sprint(fm["name"]), e, m)
		val, err2 := crypto.DecryptString(fmt.Sprint(fm["value"]), e, m)
		if err1 == nil && err2 == nil && name == testManagedField && val == "true" {
			return true
		}
	}
	return false
}

// M1: PushSecret and DeleteSecret must not touch a same-named item that a
// human created (a Login here), and must not hard-delete anything.
func TestPushAndDeleteRefuseUnmanagedItems(t *testing.T) {
	t.Parallel()
	k := newHostileKeys(t)
	humanLogin := map[string]any{"id": "human-login-1", "type": 1, "organizationId": nil, "deletedDate": nil,
		"name":  encS(t, "prod-admin", k.userEnc, k.userMac),
		"login": map[string]any{"username": encS(t, "root", k.userEnc, k.userMac), "password": encS(t, "hunter2", k.userEnc, k.userMac)}}
	unmarkedNote := map[string]any{"id": "human-note-1", "type": 2, "organizationId": nil, "deletedDate": nil,
		"name": encS(t, "runbook", k.userEnc, k.userMac), "notes": encS(t, "human text", k.userEnc, k.userMac)}
	fv := &hostileServer{profile: k.personalProfile(), ciphers: []map[string]any{humanLogin, unmarkedNote}}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})

	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("whatever")}}
	for _, name := range []string{"prod-admin", "runbook"} {
		err := c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: name})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "not managed by external-secrets")
		err = c.DeleteSecret(context.Background(), testPushData{remoteKey: name})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "not managed by external-secrets")
	}
	assert.Empty(t, fv.puts)
	assert.Empty(t, fv.posted)
	for _, r := range fv.requests() {
		assert.False(t, strings.HasPrefix(r, http.MethodDelete), "unexpected %s", r)
	}
}

// M1: items ESO creates carry the managed marker; ESO updates and soft-deletes
// its own items, path-escaping the server-supplied ID.
func TestPushAndDeleteManagedItems(t *testing.T) {
	t.Parallel()
	k := newHostileKeys(t)
	const oddID = "a/../b?c"
	fv := &hostileServer{profile: k.personalProfile(), ciphers: []map[string]any{managedNote(t, k, oddID, "app-db", "old")}}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("new-value")}}

	// Create.
	require.NoError(t, c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "fresh"}))
	require.Len(t, fv.posted, 1)
	assert.True(t, hasManagedMarker(t, fv.posted[0], k.userEnc, k.userMac), "created item lacks the managed marker")

	// Update keeps the marker and escapes the ID.
	require.NoError(t, c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "app-db"}))
	escaped := "a%2F..%2Fb%3Fc"
	body, ok := fv.puts[escaped]
	require.True(t, ok, "PUT paths: %v", fv.requests())
	assert.True(t, hasManagedMarker(t, body, k.userEnc, k.userMac))

	// Delete is a soft delete.
	require.NoError(t, c.DeleteSecret(context.Background(), testPushData{remoteKey: "app-db"}))
	assert.Contains(t, fv.requests(), http.MethodPut+" /api/ciphers/"+escaped+"/delete")
	for _, r := range fv.requests() {
		assert.False(t, strings.HasPrefix(r, http.MethodDelete), "unexpected hard delete %s", r)
	}

	// Deleting something that does not exist is a no-op.
	require.NoError(t, c.DeleteSecret(context.Background(), testPushData{remoteKey: "missing"}))
}

// M1: a missing secret is reported as esv1.NoSecretErr.
func TestGetSecretNotFoundIsNoSecretErr(t *testing.T) {
	t.Parallel()
	k := newHostileKeys(t)
	srv := httptest.NewTLSServer(&hostileServer{profile: k.personalProfile()})
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "missing"})
	assert.ErrorIs(t, err, esv1.NoSecretErr)
	_, err = c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "missing"})
	assert.ErrorIs(t, err, esv1.NoSecretErr)
}

// L6: only absolute https:// URLs are accepted.
func TestValidateStoreRequiresHTTPS(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	for _, u := range []string{"", "http://vw.example.com", "vw.example.com", "ftp://vw.example.com", "https://", "https://user:pw@vw.example.com"} {
		_, err := p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: u}))
		assert.Error(t, err, "url %q", u)
	}
	_, err := p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com/base"}))
	assert.NoError(t, err)
}

// L4/L6: organizationName must not be blank, and using it draws a warning
// recommending organizationId.
func TestValidateStoreOrganizationName(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	_, err := p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationName: "   "}))
	assert.Error(t, err)
	w, err := p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationName: "Example"}))
	require.NoError(t, err)
	assert.True(t, containsSubstring(w, "organizationId"), "warnings: %v", w)
	w, err = p.ValidateStore(newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com", OrganizationID: testOrgID}))
	require.NoError(t, err)
	assert.False(t, containsSubstring(w, "organizationName"), "warnings: %v", w)
}

// L6: the production HTTP client must not follow redirects: a 307 from the
// token endpoint would re-send client_id/client_secret to the redirect target.
func TestTokenRequestDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var leaked []string
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		leaked = append(leaked, r.Method+" "+r.URL.Path+" "+r.Form.Encode())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"stolen"}`))
	}))
	defer srvB.Close()
	srvA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/steal"+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srvA.Close()

	scheme := k8sruntime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	kube := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(hostileCredsKube(t)).Build()
	prov := esv1.VaultwardenProvider{
		URL:      srvA.URL,
		CABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvA.Certificate().Raw}),
		Auth: esv1.VaultwardenAuth{SecretRef: esv1.VaultwardenSecretRef{
			ClientID:       esmeta.SecretKeySelector{Name: "vw", Key: "clientID"},
			ClientSecret:   esmeta.SecretKeySelector{Name: "vw", Key: "clientSecret"},
			MasterPassword: esmeta.SecretKeySelector{Name: "vw", Key: "masterPassword"},
		}},
	}
	store := &esv1.SecretStore{Kind: esv1.SecretStoreKind, Name: "vw-store", Namespace: "default",
		Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{Vaultwarden: &prov}}}
	sc, err := (&Provider{}).NewClient(context.Background(), store, kube, "default")
	require.NoError(t, err)
	c := sc.(*Client)

	_, err = c.getToken(context.Background())
	require.Error(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, leaked, "credentials followed a redirect")
}

// L6: NewClient refuses a non-https URL even if admission was bypassed.
func TestNewClientRequiresHTTPS(t *testing.T) {
	t.Parallel()
	store := newStore(&esv1.VaultwardenProvider{URL: "http://vw.example.com"})
	_, err := (&Provider{}).NewClient(context.Background(), store, nil, "default")
	assert.Error(t, err)
}

type idleSpyTransport struct {
	http.RoundTripper
	closed bool
}

func (s *idleSpyTransport) CloseIdleConnections() { s.closed = true }

// Info: the transport honors proxy settings and Close releases idle connections.
func TestHTTPClientHygiene(t *testing.T) {
	t.Parallel()
	store := newStore(&esv1.VaultwardenProvider{URL: "https://vw.example.com"})
	sc, err := (&Provider{}).NewClient(context.Background(), store, nil, "default")
	require.NoError(t, err)
	c := sc.(*Client)
	tr, ok := c.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, tr.Proxy)
	assert.NotNil(t, c.httpClient.CheckRedirect)

	spy := &idleSpyTransport{RoundTripper: tr}
	c.httpClient.Transport = spy
	require.NoError(t, c.Close(context.Background()))
	assert.True(t, spy.closed)
}

// personalNoteServer serves one personal SecureNote "db-password" = "personal-value".
func personalNoteServer(t *testing.T) (*hostileServer, *httptest.Server) {
	t.Helper()
	k := newHostileKeys(t)
	fv := &hostileServer{profile: k.personalProfile(), ciphers: []map[string]any{managedNote(t, k, "p1", "db-password", "personal-value")}}
	srv := httptest.NewTLSServer(fv)
	t.Cleanup(srv.Close)
	return fv, srv
}

// M4a: N data[] entries in one reconcile cost one /api/sync, and a write
// invalidates the memoised list.
func TestCipherListMemoisedPerClient(t *testing.T) {
	t.Parallel()
	fv, srv := personalNoteServer(t)
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	for range 3 {
		v, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
		require.NoError(t, err)
		assert.Equal(t, "personal-value", string(v))
	}
	assert.Equal(t, 1, fv.count("GET /api/sync"))

	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	require.NoError(t, c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "new"}))
	syncs := fv.count("GET /api/sync")
	_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
	require.NoError(t, err)
	assert.Equal(t, syncs+1, fv.count("GET /api/sync"), "list not refreshed after a write")
}

// M4b: successive clients for the same store and credentials (one per
// reconcile in ESO) reuse the login and unlocked keys.
func TestSessionReusedAcrossClients(t *testing.T) {
	t.Parallel()
	fv, srv := personalNoteServer(t)
	for range 3 {
		c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
		v, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
		require.NoError(t, err)
		assert.Equal(t, "personal-value", string(v))
		require.NoError(t, c.Close(context.Background()))
	}
	assert.Equal(t, 1, fv.count("POST /identity/connect/token"))
	assert.Equal(t, 1, fv.count("GET /api/accounts/profile"))
}

// M4b: sessions are never shared across stores or credentials.
func TestSessionNotSharedAcrossStoresOrCredentials(t *testing.T) {
	t.Parallel()
	fv, srv := personalNoteServer(t)
	get := func(c *Client) {
		t.Helper()
		_, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
		require.NoError(t, err)
	}
	base := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	get(base)

	other := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	other.store.(*esv1.SecretStore).Name = "other-store"
	get(other)
	assert.Equal(t, 2, fv.count("POST /identity/connect/token"), "different store must log in separately")

	otherNS := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	otherNS.store.(*esv1.SecretStore).Namespace = "other-ns"
	get(otherNS)
	assert.Equal(t, 3, fv.count("POST /identity/connect/token"), "same name in another namespace must log in separately")

	rotated := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	creds := hostileCredsKube(t)
	creds.Data["clientSecret"] = []byte("ROTATED")
	require.NoError(t, rotated.crClient.Update(context.Background(), creds))
	get(rotated)
	assert.Equal(t, 4, fv.count("POST /identity/connect/token"), "rotated credentials must log in again")
}

// M4b/L5: concurrent clients sharing a session do not disturb each other,
// including when one of them is closed (its keys zeroed) mid-flight.
func TestSessionConcurrentUse(t *testing.T) {
	t.Parallel()
	_, srv := personalNoteServer(t)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 16 {
		wg.Go(func() {
			c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
			v, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
			if err == nil && string(v) != "personal-value" {
				err = fmt.Errorf("got %q", v)
			}
			errs <- err
			errs <- c.Close(context.Background())
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}

// L5: Close must not zero keys out from under an operation in flight on the
// same client.
func TestCloseWaitsForInFlightOperation(t *testing.T) {
	t.Parallel()
	k := newHostileKeys(t)
	fv := &hostileServer{profile: k.personalProfile(), ciphers: []map[string]any{managedNote(t, k, "p1", "db-password", "personal-value")}}
	arrived, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fv.syncHook = func(w http.ResponseWriter, _ *http.Request) bool {
		once.Do(func() { close(arrived) })
		<-release
		return false
	}
	srv := httptest.NewTLSServer(fv)
	defer srv.Close()
	c := newHostileClient(t, srv, esv1.VaultwardenProvider{})

	type result struct {
		v   []byte
		err error
	}
	got := make(chan result, 1)
	go func() {
		v, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
		got <- result{v, err}
	}()
	<-arrived
	closed := make(chan error, 1)
	go func() { closed <- c.Close(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	r := <-got
	require.NoError(t, r.err)
	assert.Equal(t, "personal-value", string(r.v))
	require.NoError(t, <-closed)
}

// deviceIDServer records the DeviceIdentifier of each token request.
func deviceIDServer(t *testing.T) (*[]string, *httptest.Server) {
	t.Helper()
	k := newHostileKeys(t)
	fv := &hostileServer{profile: k.personalProfile()}
	var mu sync.Mutex
	ids := &[]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/connect/token" {
			_ = r.ParseForm()
			mu.Lock()
			*ids = append(*ids, r.PostForm.Get("DeviceIdentifier"))
			mu.Unlock()
		}
		fv.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return ids, srv
}

// M4c: the device identifier depends only on the store's identity: a
// ClusterSecretStore is one device whichever namespace uses it.
func TestDeviceIdentifierFromStoreIdentity(t *testing.T) {
	t.Parallel()
	ids, srv := deviceIDServer(t)
	newCSSClient := func(ns string) *Client {
		c := newHostileClient(t, srv, esv1.VaultwardenProvider{})
		c.store = &esv1.ClusterSecretStore{Kind: esv1.ClusterSecretStoreKind, Name: "shared-vw",
			Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{Vaultwarden: c.provider}}}
		c.namespace = ns
		// Give the second namespace its own credentials secret, with a
		// different API key so it does not reuse the first login.
		if ns != "default" {
			creds := hostileCredsKube(t)
			creds.Namespace = ns
			creds.Data["clientSecret"] = []byte("team-b-client-secret")
			require.NoError(t, c.crClient.Create(context.Background(), creds))
		}
		return c
	}
	for _, ns := range []string{"default", "team-b"} {
		_, err := newCSSClient(ns).getToken(context.Background())
		require.NoError(t, err)
	}
	ssClient := newHostileClient(t, srv, esv1.VaultwardenProvider{})
	ssClient.store.(*esv1.SecretStore).Name = "shared-vw"
	_, err := ssClient.getToken(context.Background())
	require.NoError(t, err)

	require.Len(t, *ids, 3)
	assert.Equal(t, (*ids)[0], (*ids)[1], "ClusterSecretStore device ID must not depend on the requesting namespace")
	assert.NotEqual(t, (*ids)[0], (*ids)[2], "a SecretStore is a different device from a same-named ClusterSecretStore")
}

// L5: the master key passed in, and the intermediates derived from it, are
// zeroed; the returned user keys are independent copies.
func TestUnlockUserKeyZeroesMasterKey(t *testing.T) {
	t.Parallel()
	k := newHostileKeys(t)
	mk, err := testMasterKey()
	require.NoError(t, err)
	masterKey := bytes.Clone(mk)

	enc, mac, err := unlockUserKey(masterKey, k.protectedUserKey)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(masterKey)), masterKey, "master key not zeroed")
	assert.Equal(t, k.userEnc, enc)
	assert.Equal(t, k.userMac, mac)
	assert.Equal(t, 32, cap(enc), "enc must not alias the decrypted buffer")

	masterKey = bytes.Clone(mk)
	_, _, err = unlockUserKey(masterKey, "2.bad|bad|bad")
	require.Error(t, err)
	assert.Equal(t, make([]byte, len(masterKey)), masterKey, "master key not zeroed on error")
}

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
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func TestCachedTokenInvalidateZeroes(t *testing.T) {
	symEnc, symMac, orgEnc, orgMac := make32(1), make32(33), make32(65), make32(97)
	tok := &cachedToken{
		accessToken: "bearer-xxx",
		symEncKey:   symEnc, symMacKey: symMac,
		orgID:     testOrgID,
		orgEncKey: orgEnc, orgMacKey: orgMac,
	}
	tok.invalidate()

	zero := make([]byte, 32)
	for name, b := range map[string][]byte{"symEnc": symEnc, "symMac": symMac, "orgEnc": orgEnc, "orgMac": orgMac} {
		assert.Equal(t, zero, b, "%s backing array not zeroed", name)
	}
	assert.Empty(t, tok.accessToken)
	assert.Empty(t, tok.orgID)
	assert.Nil(t, tok.symEncKey)
	assert.Nil(t, tok.orgEncKey)
}

func TestCloseZeroesCachedKeys(t *testing.T) {
	_, c := newFakeVaultwarden(t, esv1.VaultwardenProvider{OrganizationName: "Example"})
	tok, err := c.getToken(context.Background())
	require.NoError(t, err)
	symEnc, orgEnc := tok.symEncKey, tok.orgEncKey

	require.NoError(t, c.Close(context.Background()))
	assert.Equal(t, make([]byte, 32), symEnc)
	assert.Equal(t, make([]byte, 32), orgEnc)
	assert.Nil(t, c.cache)

	// A closed client re-authenticates rather than using zeroed keys.
	val, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db-password"})
	require.NoError(t, err)
	assert.Equal(t, "org-value", string(val))
}

func newTLSTestClient(t *testing.T, url string, caBundle []byte) esv1.SecretsClient {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	store := &esv1.SecretStore{
		Name: "vw", Namespace: "default",
		Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{
			Vaultwarden: &esv1.VaultwardenProvider{URL: url, CABundle: caBundle},
		}},
	}
	c, err := (&Provider{}).NewClient(context.Background(), store, clientfake.NewClientBuilder().WithScheme(scheme).Build(), "default")
	require.NoError(t, err)
	return c
}

// The client must verify server certificates (no InsecureSkipVerify) and
// trust a self-signed server only when its CA is supplied via caBundle.
func TestTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ciphers":[]}`))
	}))
	defer srv.Close()

	untrusted := newTLSTestClient(t, srv.URL, nil).(*Client)
	_, err := untrusted.listCiphers(context.Background(), &cachedToken{accessToken: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	trusted := newTLSTestClient(t, srv.URL, caPEM).(*Client)
	_, err = trusted.listCiphers(context.Background(), &cachedToken{accessToken: "x"})
	assert.NoError(t, err)
}

// Credentials must never appear in errors returned from the auth path.
func TestAuthErrorsDoNotLeakCredentials(t *testing.T) {
	const (
		clientSecret   = "super-secret-client-secret"
		masterPassword = "super-secret-master-pw"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the request body back in an error response, as a misbehaving
		// server or proxy might.
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		http.Error(w, buf.String(), http.StatusBadRequest)
	}))
	defer srv.Close()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	kube := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		Name: "vw", Namespace: "default",
		Data: map[string][]byte{
			"clientID": []byte("user.fake"), "clientSecret": []byte(clientSecret), "masterPassword": []byte(masterPassword),
		},
	}).Build()
	prov := &esv1.VaultwardenProvider{
		URL: srv.URL,
		Auth: esv1.VaultwardenAuth{SecretRef: esv1.VaultwardenSecretRef{
			ClientID:       esmeta.SecretKeySelector{Name: "vw", Key: "clientID"},
			ClientSecret:   esmeta.SecretKeySelector{Name: "vw", Key: "clientSecret"},
			MasterPassword: esmeta.SecretKeySelector{Name: "vw", Key: "masterPassword"},
		}},
	}
	store := &esv1.SecretStore{
		Kind: esv1.SecretStoreKind,
		Name: "vw", Namespace: "default",
		Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{Vaultwarden: prov}},
	}
	c := &Client{httpClient: srv.Client(), provider: prov, crClient: kube, namespace: "default", store: store}

	_, err := c.getToken(context.Background())
	require.Error(t, err)
	for _, s := range []string{clientSecret, masterPassword} {
		assert.NotContains(t, err.Error(), s)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Write-path error responses are not echoed into the returned error (they can
// contain request content, i.e. the encrypted secret or server internals).
func TestWriteErrorsDoNotEchoResponseBody(t *testing.T) {
	const marker = "SERVER-ECHOED-BODY"
	_, c := newFakeVaultwarden(t, esv1.VaultwardenProvider{})
	inner := c.httpClient.Transport
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/ciphers" {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(marker)),
				Header:     http.Header{},
				Request:    r,
			}, nil
		}
		return inner.RoundTrip(r)
	})
	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	err := c.PushSecret(context.Background(), secret, testPushData{secretKey: "k", remoteKey: "x"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), marker)
}

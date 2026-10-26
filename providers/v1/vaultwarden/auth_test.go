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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

const testOrgID = "af061424-2700-425a-8800-80e988194e8e"

func make32(start byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// wrapOrgKey RSA-OAEP-SHA1 encrypts orgKey for pub, as Bitwarden does for org members.
func wrapOrgKey(t *testing.T, pub *rsa.PublicKey, orgKey []byte) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, orgKey, nil)
	require.NoError(t, err)
	return "4." + base64.StdEncoding.EncodeToString(ct)
}

// fakeOrgProfile builds a profile whose privateKey is encrypted with the given
// user symmetric key and which contains one org wrapping orgKey.
func fakeOrgProfile(t *testing.T, symEnc, symMac, orgKey []byte, orgName string) *vaultwardenProfile {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	encPriv, err := crypto.Encrypt(der, symEnc, symMac)
	require.NoError(t, err)
	return &vaultwardenProfile{
		PrivateKey: encPriv,
		Organizations: []orgEntry{
			{ID: "11111111-1111-1111-1111-111111111111", Name: "Other", Key: wrapOrgKey(t, &priv.PublicKey, make([]byte, 64))},
			{ID: testOrgID, Name: orgName, Key: wrapOrgKey(t, &priv.PublicKey, orgKey)},
		},
	}
}

func TestUnlockOrgKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	orgKey := make([]byte, 64)
	_, err = rand.Read(orgKey)
	require.NoError(t, err)

	enc, mac, fp, err := unlockOrgKey(wrapOrgKey(t, &priv.PublicKey, orgKey), priv)
	require.NoError(t, err)
	assert.Equal(t, orgKey[:32], enc)
	assert.Equal(t, orgKey[32:], mac)
	assert.Equal(t, sha256.Sum256(orgKey), fp)

	_, _, _, err = unlockOrgKey(wrapOrgKey(t, &priv.PublicKey, make([]byte, 32)), priv) //nolint:dogsled // only the error matters
	assert.ErrorContains(t, err, "unexpected length")
}

func TestResolveOrgByName(t *testing.T) {
	profile := &vaultwardenProfile{
		Organizations: []orgEntry{
			{ID: "uuid-a", Name: "Example-Grail", Key: "4.aaa"},
			{ID: "uuid-b", Name: "Example", Key: "4.bbb"},
			{ID: "uuid-c", Name: "Example", Key: "4.ccc"},
		},
	}

	id, key, err := resolveOrgByName(profile, "Example-Grail")
	require.NoError(t, err)
	assert.Equal(t, "uuid-a", id)
	assert.Equal(t, "4.aaa", key)

	_, _, err = resolveOrgByName(profile, "Example")
	assert.ErrorContains(t, err, "use organizationId")

	_, _, err = resolveOrgByName(profile, "Nonexistent")
	assert.ErrorContains(t, err, "no organization named")
}

func TestUnlockOrgScope(t *testing.T) {
	symEnc, symMac := make32(1), make32(33)
	orgKey := append(make32(65), make32(97)...)
	profile := fakeOrgProfile(t, symEnc, symMac, orgKey, "Example")

	cases := []struct {
		name     string
		provider esv1.VaultwardenProvider
		wantOrg  string
		wantErr  string
	}{
		{name: "personal scope is a no-op", provider: esv1.VaultwardenProvider{}},
		{name: "by id", provider: esv1.VaultwardenProvider{OrganizationID: testOrgID}, wantOrg: testOrgID},
		{name: "by name", provider: esv1.VaultwardenProvider{OrganizationName: "Example"}, wantOrg: testOrgID},
		{name: "unknown id", provider: esv1.VaultwardenProvider{OrganizationID: "22222222-2222-2222-2222-222222222222"}, wantErr: "not found"},
		{name: "unknown name", provider: esv1.VaultwardenProvider{OrganizationName: "Nope"}, wantErr: "no organization named"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{provider: &tc.provider}
			tok := &cachedToken{symEncKey: symEnc, symMacKey: symMac}
			err := c.unlockOrgScope(profile, tok)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantOrg, tok.orgID)
			if tc.wantOrg == "" {
				assert.Nil(t, tok.orgEncKey)
				return
			}
			assert.Equal(t, orgKey[:32], tok.orgEncKey)
			assert.Equal(t, orgKey[32:], tok.orgMacKey)
		})
	}
}

// The user's RSA private key is encrypted with the user symmetric key, not the
// stretched master key; decrypting it with any other key must fail.
func TestUnlockOrgScopeWrongUserKey(t *testing.T) {
	profile := fakeOrgProfile(t, make32(1), make32(33), make([]byte, 64), "Example")
	c := &Client{provider: &esv1.VaultwardenProvider{OrganizationName: "Example"}}
	err := c.unlockOrgScope(profile, &cachedToken{symEncKey: make32(2), symMacKey: make32(34)})
	assert.ErrorContains(t, err, "decrypting user private key")
}

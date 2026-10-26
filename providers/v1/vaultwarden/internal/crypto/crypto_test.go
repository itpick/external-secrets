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

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deterministicTestKeys returns fixed enc/mac keys for deterministic tests.
func deterministicTestKeys() (encKey, macKey []byte) {
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i + 1)
	}
	for i := range macKey {
		macKey[i] = byte(i + 33)
	}
	return
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	encKey, macKey := deterministicTestKeys()

	plaintext := "hello, vaultwarden!"
	enc, err := EncryptString(plaintext, encKey, macKey)
	require.NoError(t, err)
	assert.Contains(t, enc, "2.")

	got, err := DecryptString(enc, encKey, macKey)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestMACValidation(t *testing.T) {
	encKey, macKey := deterministicTestKeys()

	enc, err := EncryptString("test", encKey, macKey)
	require.NoError(t, err)

	// Tamper with the MAC by using the wrong macKey
	wrongMacKey := make([]byte, 32)
	es, err := ParseEncString(enc)
	require.NoError(t, err)
	_, err = Decrypt(es, encKey, wrongMacKey)
	assert.ErrorContains(t, err, "MAC validation failed")
}

func TestDeriveKeyPBKDF2(t *testing.T) {
	key, err := DeriveKey("parolaribame4", "test@vaultwarden.local", KdfTypePBKDF2, 600000, 0, 0)
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestStretchKey(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	encKey, macKey, err := StretchKey(masterKey)
	require.NoError(t, err)
	assert.Len(t, encKey, 32)
	assert.Len(t, macKey, 32)
	assert.NotEqual(t, encKey, macKey)
}

func TestRSAOAEPRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	plaintext := make([]byte, 64)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	got, err := DecryptRSAOAEP("4."+base64.StdEncoding.EncodeToString(ct), priv)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	_, err = DecryptRSAOAEP("2."+base64.StdEncoding.EncodeToString(ct), priv)
	assert.Error(t, err)
}

func TestRSAPrivateKeyFromPKCS8DER(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	parsed, err := RSAPrivateKeyFromPKCS8DER(der)
	require.NoError(t, err)
	assert.Zero(t, parsed.N.Cmp(priv.N))

	_, err = RSAPrivateKeyFromPKCS8DER([]byte("not a key"))
	assert.Error(t, err)
}

func TestDecryptStringBytes(t *testing.T) {
	encKey, macKey := deterministicTestKeys()
	enc, err := Encrypt([]byte{0, 1, 2, 0xff}, encKey, macKey)
	require.NoError(t, err)
	got, err := DecryptStringBytes(enc, encKey, macKey)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 1, 2, 0xff}, got)

	got, err = DecryptStringBytes("", encKey, macKey)
	require.NoError(t, err)
	assert.Nil(t, got)
}

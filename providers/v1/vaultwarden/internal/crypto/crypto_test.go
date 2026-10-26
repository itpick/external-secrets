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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
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
	assert.ErrorIs(t, err, errInvalidCiphertext)
}

func TestDeriveKeyPBKDF2(t *testing.T) {
	key, err := DeriveKey(context.Background(), "parolaribame4", "test@vaultwarden.local", KdfTypePBKDF2, 600000, 0, 0)
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

// Every decrypt-side failure must surface the same error so the API cannot be
// used as a padding/format oracle.
func TestDecryptErrorsAreIndistinguishable(t *testing.T) {
	encKey, macKey := deterministicTestKeys()

	valid, err := EncryptString("hello-from-vault", encKey, macKey)
	require.NoError(t, err)
	parts := strings.Split(strings.TrimPrefix(valid, "2."), "|")
	macBytes, err := base64.StdEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	macBytes[len(macBytes)-1] ^= 0x01
	tamperedMAC := "2." + parts[0] + "|" + parts[1] + "|" + base64.StdEncoding.EncodeToString(macBytes)

	// Valid MAC over a ciphertext whose plaintext has invalid PKCS#7 padding.
	iv := make([]byte, aes.BlockSize)
	plaintext := make([]byte, 32)
	plaintext[31] = 0xFF
	block, err := aes.NewCipher(encKey)
	require.NoError(t, err)
	ct := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plaintext)
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	badPadding := "2." + base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct) + "|" + base64.StdEncoding.EncodeToString(h.Sum(nil))

	for name, in := range map[string]string{
		"tampered mac":   tamperedMAC,
		"bad padding":    badPadding,
		"no type prefix": "garbage",
		"wrong type":     "0." + parts[0] + "|" + parts[1] + "|" + parts[2],
		"missing parts":  "2." + parts[0],
		"bad base64":     "2.!!|!!|!!",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptString(in, encKey, macKey)
			assert.ErrorIs(t, err, errInvalidCiphertext)
			assert.Equal(t, errInvalidCiphertext.Error(), err.Error())
		})
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = DecryptRSAOAEP("4."+base64.StdEncoding.EncodeToString(make([]byte, 256)), priv)
	assert.ErrorIs(t, err, errInvalidCiphertext)
}

func TestDeriveKeyPBKDF2IterationBounds(t *testing.T) {
	for _, iters := range []int{0, 1, MinPBKDF2Iterations - 1, MaxPBKDF2Iterations + 1} {
		_, err := DeriveKey(context.Background(), "pw", "a@b.c", KdfTypePBKDF2, iters, 0, 0)
		require.Error(t, err, "iterations=%d", iters)
	}
}

func TestDeriveKeyCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := DeriveKey(ctx, "pw", "a@b.c", KdfTypePBKDF2, MaxPBKDF2Iterations, 0, 0)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 200*time.Millisecond)
}

// pbkdf2SHA256 must match RFC 7914 section 11 (PBKDF2-HMAC-SHA256, first
// 32 bytes) and the reference implementation.
func TestPBKDF2SHA256KnownAnswers(t *testing.T) {
	got, err := pbkdf2SHA256(context.Background(), []byte("passwd"), []byte("salt"), 1)
	require.NoError(t, err)
	want, _ := hex.DecodeString("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
	assert.Equal(t, want, got)

	got, err = pbkdf2SHA256(context.Background(), []byte("Password"), []byte("NaCl"), 80000)
	require.NoError(t, err)
	assert.Equal(t, pbkdf2.Key([]byte("Password"), []byte("NaCl"), 80000, 32, sha256.New), got)
}

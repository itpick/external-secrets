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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// ESO builds a new Client for every reconcile, so a token cached only on the
// Client meant a full login (token request, profile fetch and PBKDF2 over up
// to 2M iterations) per reconcile. sessions keeps the token and unlocked keys
// across Clients for a short TTL.
//
// Entries are keyed by an HMAC (with a random per-process key) over the store's
// identity (kind, namespace, name, UID), the server URL, the scope settings and
// the resolved credential values themselves. Keys are therefore never shared
// across stores, and any credential change, including an in-place rotation,
// selects a new entry. The cache stores its own copy of the key material and
// hands out copies, so a Client zeroing its keys on Close never affects another
// Client; the cache zeroes its copy when the entry expires or is replaced.
var sessions = newSessionCache()

const (
	// sessionTTL is how long a login is reused. Vaultwarden access tokens
	// last 2h by default; the TTL is further capped below the token's own
	// expires_in (see sessionLifetime).
	sessionTTL = 5 * time.Minute
	// sessionExpirySlack is kept between the end of reuse and token expiry.
	sessionExpirySlack = time.Minute
	// maxSessions bounds the cache; when full, arbitrary entries are evicted.
	maxSessions = 1024
)

type sessionKey [sha256.Size]byte

type sessionCache struct {
	mu      sync.Mutex
	hmacKey []byte
	entries map[sessionKey]*cachedToken
}

func newSessionCache() *sessionCache {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("vaultwarden: crypto/rand failed: " + err.Error())
	}
	return &sessionCache{hmacKey: k, entries: map[sessionKey]*cachedToken{}}
}

// key derives the cache key from length-prefixed parts.
func (s *sessionCache) key(parts ...string) sessionKey {
	m := hmac.New(sha256.New, s.hmacKey)
	for _, p := range parts {
		var l [8]byte
		binary.LittleEndian.PutUint64(l[:], uint64(len(p)))
		m.Write(l[:])
		m.Write([]byte(p))
	}
	var k sessionKey
	copy(k[:], m.Sum(nil))
	return k
}

// get returns a copy of the live entry for k, or nil.
func (s *sessionCache) get(k sessionKey, now time.Time) *cachedToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.entries[k]
	if !ok {
		return nil
	}
	if !now.Before(t.expiresAt) {
		delete(s.entries, k)
		t.invalidate()
		return nil
	}
	return t.clone()
}

// put stores a copy of t under k, replacing (and zeroing) any previous entry.
func (s *sessionCache) put(k sessionKey, t *cachedToken, now time.Time) {
	if !now.Before(t.expiresAt) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ek, e := range s.entries {
		if ek == k || !now.Before(e.expiresAt) || len(s.entries) >= maxSessions {
			delete(s.entries, ek)
			e.invalidate()
		}
	}
	s.entries[k] = t.clone()
}

// drop removes and zeroes the entry for k (e.g. after the server rejects its token).
func (s *sessionCache) drop(k sessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[k]; ok {
		delete(s.entries, k)
		e.invalidate()
	}
}

// sessionLifetime returns how long a token that the server says expires in
// expiresIn seconds may be reused: sessionTTL, but never closer than
// sessionExpirySlack to the token's expiry.
func sessionLifetime(expiresIn int) time.Duration {
	if expiresIn <= 0 {
		return sessionTTL
	}
	return min(sessionTTL, time.Duration(expiresIn)*time.Second-sessionExpirySlack)
}

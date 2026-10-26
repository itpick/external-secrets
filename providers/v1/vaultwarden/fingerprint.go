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
	"encoding/hex"
	"errors"
	"net/http"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// OrganizationKeyFingerprint logs in to the Vaultwarden server at baseURL,
// unlocks the organization identified by organizationID and returns the value
// to put in a store's organizationKeyFingerprint: the lowercase hex SHA-256 of
// the 64-byte organization key. The fingerprint is not secret, but it is only
// as trustworthy as the server and network path it was obtained over.
func OrganizationKeyFingerprint(ctx context.Context, httpClient *http.Client, baseURL, organizationID, clientID, clientSecret, masterPassword string) (string, error) {
	if organizationID == "" {
		return "", errors.New("vaultwarden: organization ID is required")
	}
	c := &Client{
		httpClient: httpClient,
		provider:   &esv1.VaultwardenProvider{URL: baseURL, OrganizationID: organizationID},
		store:      &esv1.SecretStore{Name: "vw-org-fingerprint"},
	}
	t, err := c.authenticate(ctx, &credentials{clientID: clientID, clientSecret: clientSecret, masterPassword: masterPassword})
	if err != nil {
		return "", err
	}
	defer t.invalidate()
	return hex.EncodeToString(t.orgKeyFingerprint[:]), nil
}

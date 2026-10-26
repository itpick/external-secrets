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
	"testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func newStore(provider *esv1.VaultwardenProvider) *esv1.SecretStore {
	return &esv1.SecretStore{
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{Vaultwarden: provider},
		},
	}
}

func TestValidateStoreOrgXOR(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name    string
		orgID   string
		orgName string
		wantErr bool
	}{
		{"both empty - personal scope OK", "", "", false},
		{"id only - OK", "af061424-2700-425a-8800-80e988194e8e", "", false},
		{"name only - OK", "", "Example-Org", false},
		{"both set - rejected", "af061424-2700-425a-8800-80e988194e8e", "Example-Org", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &esv1.VaultwardenProvider{
				URL:              "https://vault.example.com",
				OrganizationID:   tc.orgID,
				OrganizationName: tc.orgName,
			}
			_, err := p.ValidateStore(newStore(provider))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

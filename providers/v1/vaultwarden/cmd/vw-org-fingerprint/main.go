//go:build vaultwarden

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

// Command vw-org-fingerprint prints the organizationKeyFingerprint value for a
// Vaultwarden organization, for pinning in a SecretStore. Run it once from a
// trusted network path:
//
//	VW_URL=https://vault.example.com VW_CLIENT_ID=user.xxx VW_CLIENT_SECRET=... \
//	VW_MASTER_PASSWORD=... VW_ORGANIZATION_ID=<uuid> \
//	go run -tags vaultwarden ./providers/v1/vaultwarden/cmd/vw-org-fingerprint
//
// Set VW_CA_BUNDLE_FILE to a PEM file to trust a private CA.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	env := map[string]string{}
	for _, k := range []string{"VW_URL", "VW_ORGANIZATION_ID", "VW_CLIENT_ID", "VW_CLIENT_SECRET", "VW_MASTER_PASSWORD"} {
		v := os.Getenv(k)
		if v == "" {
			return fmt.Errorf("%s must be set", k)
		}
		env[k] = v
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile := os.Getenv("VW_CA_BUNDLE_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied path
		if err != nil {
			return fmt.Errorf("reading VW_CA_BUNDLE_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates in %s", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	httpClient := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fp, err := vaultwarden.OrganizationKeyFingerprint(ctx, httpClient, env["VW_URL"], env["VW_ORGANIZATION_ID"],
		env["VW_CLIENT_ID"], env["VW_CLIENT_SECRET"], env["VW_MASTER_PASSWORD"])
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}

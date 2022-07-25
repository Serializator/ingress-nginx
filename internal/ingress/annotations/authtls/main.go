/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authtls

import (
	"fmt"
	"strings"

	networking "k8s.io/api/networking/v1"

	"regexp"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	ing_errors "k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
	"k8s.io/ingress-nginx/internal/k8s"
)

const (
	defaultAuthTLSDepth     = 1
	defaultAuthVerifyClient = "on"
)

var (
	authVerifyClientRegex = regexp.MustCompile(`on|off|optional|optional_no_ca`)
	commonNameRegex       = regexp.MustCompile(`CN=`)
)

// Config contains the AuthSSLCert used for mutual authentication
// and the configured ValidationDepth
type Config struct {
	Certs              []resolver.AuthSSLCert `json:"certs"`
	VerifyClient       string                 `json:"verify_client"`
	ValidationDepth    int                    `json:"validationDepth"`
	ErrorPage          string                 `json:"errorPage"`
	PassCertToUpstream bool                   `json:"passCertToUpstream"`
	MatchCN            string                 `json:"matchCN"`
	AuthTLSError       string
}

// Equal tests for equality between two Config types
func (assl1 *Config) Equal(assl2 *Config) bool {
	if assl1 == assl2 {
		return true
	}
	if assl1 == nil || assl2 == nil {
		return false
	}
	if len(assl1.Certs) != len(assl2.Certs) {
		return false
	}
	for i, cert := range assl1.Certs {
		if !(&cert).Equal(&assl2.Certs[i]) {
			return false
		}
	}
	if assl1.VerifyClient != assl2.VerifyClient {
		return false
	}
	if assl1.ValidationDepth != assl2.ValidationDepth {
		return false
	}
	if assl1.ErrorPage != assl2.ErrorPage {
		return false
	}
	if assl1.PassCertToUpstream != assl2.PassCertToUpstream {
		return false
	}

	return true
}

// NewParser creates a new TLS authentication annotation parser
func NewParser(resolver resolver.Resolver) parser.IngressAnnotation {
	return authTLS{resolver}
}

type authTLS struct {
	r resolver.Resolver
}

// Parse parses the annotations contained in the ingress
// rule used to use a Certificate as authentication method
func (a authTLS) Parse(ing *networking.Ingress) (interface{}, error) {
	var err error
	config := &Config{}

	tlsAuthAnnotation, err := parser.GetStringAnnotation("auth-tls-secret", ing)
	if err != nil {
		return &Config{}, err
	}

	tlsAuthSecrets := strings.Split(tlsAuthAnnotation, ",")
	for i := range tlsAuthSecrets {
		tlsAuthSecrets[i] = strings.TrimSpace(tlsAuthSecrets[i])
	}

	var authSSLCerts []resolver.AuthSSLCert
	for _, tlsAuthSecret := range tlsAuthSecrets {
		_, _, err = k8s.ParseNameNS(tlsAuthSecret)
		if err != nil {
			return &Config{}, ing_errors.NewLocationDenied(err.Error())
		}

		authSSLCert, err := a.r.GetAuthCertificate(tlsAuthSecret)
		if err != nil {
			e := fmt.Errorf("error obtaining certificate: %w", err)
			return &Config{}, ing_errors.LocationDenied{Reason: e}
		}

		authSSLCerts = append(authSSLCerts, *authSSLCert)
	}

	config.Certs = authSSLCerts

	config.VerifyClient, err = parser.GetStringAnnotation("auth-tls-verify-client", ing)
	if err != nil || !authVerifyClientRegex.MatchString(config.VerifyClient) {
		config.VerifyClient = defaultAuthVerifyClient
	}

	config.ValidationDepth, err = parser.GetIntAnnotation("auth-tls-verify-depth", ing)
	if err != nil || config.ValidationDepth == 0 {
		config.ValidationDepth = defaultAuthTLSDepth
	}

	config.ErrorPage, err = parser.GetStringAnnotation("auth-tls-error-page", ing)
	if err != nil {
		config.ErrorPage = ""
	}

	config.PassCertToUpstream, err = parser.GetBoolAnnotation("auth-tls-pass-certificate-to-upstream", ing)
	if err != nil {
		config.PassCertToUpstream = false
	}

	config.MatchCN, err = parser.GetStringAnnotation("auth-tls-match-cn", ing)
	if err != nil || !commonNameRegex.MatchString(config.MatchCN) {
		config.MatchCN = ""
	}

	return config, nil
}

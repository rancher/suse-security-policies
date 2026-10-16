package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

type config struct {
	Upstream struct {
		Repository                  string `json:"repository"`
		Registry                    string `json:"registry"`
		CertificateIdentityTemplate string `json:"certificate_identity_template"`
		CertificateOIDCIssuer       string `json:"certificate_oidc_issuer"`
	} `json:"upstream"`
	Destination struct {
		Registry string `json:"registry"`
	} `json:"destination"`
	Metadata struct {
		Author string `json:"author"`
		URL    string `json:"url"`
	} `json:"metadata"`
	SBOM struct {
		NamespaceBase string `json:"namespace_base"`
		Supplier      string `json:"supplier"`
		Originator    string `json:"originator"`
		ToolName      string `json:"tool_name"`
	} `json:"sbom"`
	ExcludedPolicies []string `json:"excluded_policies"`
}

func loadConfig(path string) (*config, error) {
	var c config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	errs := []error{yaml.Unmarshal(data, &c)}
	for _, kv := range [][2]string{
		{"upstream.repository", c.Upstream.Repository},
		{"upstream.registry", c.Upstream.Registry},
		{"upstream.certificate_identity_template", c.Upstream.CertificateIdentityTemplate},
		{"upstream.certificate_oidc_issuer", c.Upstream.CertificateOIDCIssuer},
		{"destination.registry", c.Destination.Registry},
		{"metadata.url", c.Metadata.URL},
		{"sbom.namespace_base", c.SBOM.NamespaceBase},
		{"sbom.supplier", c.SBOM.Supplier},
		{"sbom.originator", c.SBOM.Originator},
		{"sbom.tool_name", c.SBOM.ToolName},
	} {
		if strings.TrimSpace(kv[1]) == "" {
			errs = append(errs, fmt.Errorf("%s is missing", kv[0]))
		}
	}
	if len(c.ExcludedPolicies) == 0 {
		errs = append(errs, errors.New("excluded_policies must not be empty"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s is not valid: %w", path, err)
	}
	return &c, nil
}

package main

import (
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantOut string
		wantErr string
	}{
		{name: "check-config", args: []string{"check-config", "--config", "../../config.yaml"}, wantOut: "../../config.yaml is valid\n"},
		{name: "check-config without the file", args: []string{"check-config", "--config", "missing.yaml"}, wantErr: "missing.yaml"},
		{name: "repackage without flags", args: []string{"repackage", "--config", "testdata/config.yaml"},
			wantErr: "these flags are required and must not be empty: --repository, --sha, --policy-name, --policy-version"},
		{name: "repackage with a short sha", args: []string{"repackage", "--config", "testdata/config.yaml", "--repository", "a/b", "--sha", "abc123",
			"--policy-name", "p", "--policy-version", "1.0.0"}, wantErr: "is not a full commit SHA"},
		{name: "repackage from another repository", args: []string{"repackage", "--config", "testdata/config.yaml", "--repository", "other/suse-security-policies", "--sha", testSHA,
			"--policy-name", "p", "--policy-version", "1.0.0"},
			wantErr: `metadata.url is "https://github.com/rancher/suse-security-policies", but this run publishes from https://github.com/other/suse-security-policies.`},
		{name: "dry run from another repository", args: []string{"repackage", "--config", "testdata/config.yaml", "--repository", "other/suse-security-policies", "--sha", testSHA,
			"--policy-name", "p", "--policy-version", "1.0.0", "--dry-run"},
			wantErr: `but this run publishes from https://github.com/other/suse-security-policies.`},
		{name: "discover without flags", args: []string{"discover", "--config", "testdata/config.yaml"}, wantErr: "must not be empty: --repository"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "")
			out, err := execute(t, tt.args...)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("the command failed: %v", err)
			} else if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("the command returned the error %v, but the test expects an error with %q", err, tt.wantErr)
			}
			if out != tt.wantOut {
				t.Errorf("stdout is %q, expected %q", out, tt.wantOut)
			}
			if len(f.calls) != 0 {
				t.Errorf("the command ran tools: %q", f.calls)
			}
		})
	}
}

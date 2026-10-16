package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWithoutMetadataURL(t *testing.T) {
	data, err := os.ReadFile("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	line := "  url: https://github.com/rancher/suse-security-policies\n"
	if !strings.Contains(string(data), line) {
		t.Fatalf("testdata/config.yaml has no line %q", line)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), line, "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "metadata.url is missing") {
		t.Fatalf("loadConfig returned the error %v, but the test expects an error with %q", err, "metadata.url is missing")
	}
}

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testData(t *testing.T, work string) *repackageData {
	cfg, err := loadConfig("testdata/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return &repackageData{
		cfg: cfg, repo: "rancher/suse-security-policies", sha: testSHA, workDir: work,
		name: "pod-privileged-policy", version: "1.2.3", tag: testTag, id: "pod-privileged",
		url:               "https://github.com/kubewarden/policies/releases/tag/" + testTag,
		upstreamPublished: time.Date(2026, 1, 2, 4, 4, 5, 0, time.FixedZone("", 3600)),
		upstreamRoot:      map[string]any{"SPDXID": "SPDXRef-Package-src", "versionInfo": testCommit, "licenseDeclared": "Apache-2.0"},
		upstreamDigest:    upstreamDigest, immutableRef: suseRef,
		upstreamNamespace: "https://kubewarden.io/spdx/pod-privileged-1.2.3",
		sourceCommit:      testCommit, sourceSHA256: strings.Repeat("e", 64),
	}
}

func TestSUSESBOM(t *testing.T) {
	var outputs [][]byte
	for range 2 {
		work := t.TempDir()
		f := newFake(t, work, rule{prefix: "sbom-utility validate ", out: "valid"})
		for name, content := range map[string]string{suseWasmName: "suse wasm", upstreamSBOMName: "{}"} {
			if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		d := testData(t, work)
		// A rerun from another commit must give the same SBOM, so that it
		// matches the attestation of the earlier run.
		if len(outputs) == 1 {
			d.sha = strings.Repeat("f", 40)
		}
		if err := suseSBOM(context.Background(), d); err != nil {
			t.Fatalf("suseSBOM failed: %v", err)
		}
		if want := "sbom-utility validate --input-file $WORK/policy-sbom.spdx.json"; len(f.calls) != 1 || f.calls[0] != want {
			t.Errorf("suseSBOM ran %q, expected only %q", f.calls, want)
		}
		data, err := os.ReadFile(d.path(suseSBOMName))
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, data)
	}
	golden(t, "sbom.golden.json", outputs[0])
	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Error("two runs for the same artifact gave two different SBOMs")
	}
}

func TestCheckSUSESBOM(t *testing.T) {
	work := t.TempDir()
	f := newFake(t, work, rule{prefix: "sbom-utility validate ", out: "valid"})
	for name, content := range map[string]string{suseWasmName: "suse wasm", upstreamSBOMName: "{}"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := testData(t, work)
	d.immutableRef = ""
	if err := checkSUSESBOM(context.Background(), d); err != nil {
		t.Fatalf("checkSUSESBOM failed: %v", err)
	}
	if want := "sbom-utility validate --input-file $WORK/" + draftSUSESBOMName; len(f.calls) != 1 || f.calls[0] != want {
		t.Errorf("checkSUSESBOM ran %q, expected only %q", f.calls, want)
	}
	if _, err := os.Stat(d.path(suseSBOMName)); !os.IsNotExist(err) {
		t.Errorf("checkSUSESBOM wrote %s, which is a release asset", suseSBOMName)
	}
	data, err := os.ReadFile(d.path(draftSUSESBOMName))
	if err != nil {
		t.Fatal(err)
	}
	if want := "@sha256%3A" + strings.Repeat("0", 64) + "?"; !bytes.Contains(data, []byte(want)) {
		t.Errorf("the draft SBOM does not contain the placeholder digest %q:\n%s", want, data)
	}
}

func TestNameUUID(t *testing.T) {
	// The expected values come from Python: uuid.uuid5(uuid.NAMESPACE_URL, name).
	for name, want := range map[string]string{
		"https://example.com": "4fd35a71-71ef-5a55-a9d9-aa75c889a6d0",
		suseRef:               "2ff847c1-608d-5796-9921-69fedb2cff17",
	} {
		if got := nameUUID(name); got != want {
			t.Errorf("nameUUID(%q) = %s, expected %s", name, got, want)
		}
	}
}

func TestVersionLess(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"1.9.0", "1.10.0", true},
		{"1.10.0", "1.9.0", false},
		{"2.0.0", "2.0.0", false},
		{"0.9.9", "1.0.0", true},
	} {
		if got := versionLess(tt.a, tt.b); got != tt.want {
			t.Errorf("versionLess(%q, %q) = %v, expected %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func describes(id string) any {
	return map[string]any{"relationshipType": "DESCRIBES", "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": id}
}

func TestUpstreamRoot(t *testing.T) {
	pkg := map[string]any{"SPDXID": "SPDXRef-a"}
	for _, tt := range []struct {
		name    string
		doc     map[string]any
		wantErr string
	}{
		{"relationship", map[string]any{"relationships": []any{describes("SPDXRef-a")}, "packages": []any{pkg}}, ""},
		{"documentDescribes and the same relationship", map[string]any{"documentDescribes": []any{"SPDXRef-a"}, "relationships": []any{describes("SPDXRef-a")}, "packages": []any{pkg}}, ""},
		{"two packages", map[string]any{"documentDescribes": []any{"SPDXRef-a", "SPDXRef-b"}, "packages": []any{pkg}}, "describes 2 packages"},
		{"no package", map[string]any{"documentDescribes": []any{"SPDXRef-b"}, "packages": []any{pkg}}, "has no package"},
	} {
		got, err := upstreamRoot(tt.doc)
		if tt.wantErr == "" && (err != nil || str(got, "SPDXID") != "SPDXRef-a") {
			t.Errorf("%s: upstreamRoot returned %v, %v", tt.name, got, err)
		} else if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("%s: upstreamRoot returned the error %v, but the test expects an error with %q", tt.name, err, tt.wantErr)
		}
	}
}

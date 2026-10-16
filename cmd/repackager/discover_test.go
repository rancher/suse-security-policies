package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func releaseJSON(tag, extra string) string {
	return `{"tag_name":"` + tag + `","html_url":"https://github.com/kubewarden/policies/releases/tag/` + tag + `"` + extra + `}`
}

func metadataRule(name, id, version string) rule {
	return rule{prefix: "gh api --hostname github.com -H Accept: application/vnd.github.raw --allow-escape-sequences repos/kubewarden/policies/contents/policies/" +
		name + "/metadata.yml?ref=" + name + "%2Fv" + version,
		out: "annotations:\n  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/" + id + "\n  io.kubewarden.policy.version: " + version + "\n"}
}

const tagsCall = "gh api --hostname github.com --paginate --slurp repos/rancher/suse-security-policies/git/matching-refs/tags/"

func discoverRules() []rule {
	// gh writes the pages of --paginate --slurp as a list of lists.
	upstream := "[[" + strings.Join([]string{
		releaseJSON("pod-privileged-policy/v1.9.0", ""),
		releaseJSON("pod-privileged-policy/v1.10.0", ""),
		releaseJSON("pod-privileged-policy/v1.11.0-rc1", ""),
		releaseJSON("pod-privileged-policy/v2.0.0", `,"prerelease":true`),
		releaseJSON("pod-privileged-policy/v3.0.0", `,"draft":true`),
		releaseJSON("sleeping-policy/v1.0.0", ""),
	}, ",") + "],[" + strings.Join([]string{
		releaseJSON("capabilities-psp-policy/v1.0.0", ""),
		releaseJSON("safe-labels-policy/v2.0.0", ""),
	}, ",") + "]]"
	// A draft is the remainder of a failed run, so it does not count as released.
	dest := `[[{"tag_name":"safe-labels-policy/v2.0.0","draft":false},{"tag_name":"pod-privileged-policy/v1.10.0","draft":true}]]`
	tags := `[[{"ref":"refs/tags/safe-labels-policy/v2.0.0"}],[{"ref":"refs/tags/pod-privileged-policy/v1.0.0"}]]`
	return []rule{
		{prefix: "gh api --hostname github.com --paginate --slurp repos/kubewarden/policies/releases", out: upstream},
		{prefix: "gh api --hostname github.com --paginate --slurp repos/rancher/suse-security-policies/releases", out: dest},
		{prefix: tagsCall, out: tags},
		metadataRule("pod-privileged-policy", "pod-privileged", "1.10.0"),
		metadataRule("pod-privileged-policy", "pod-privileged", "1.9.0"),
		metadataRule("capabilities-psp-policy", "capabilities-psp", "1.0.0"),
		metadataRule("safe-labels-policy", "safe-labels", "2.0.0"),
	}
}

func TestDiscover(t *testing.T) {
	f := newFake(t, "", discoverRules()...)
	output := filepath.Join(t.TempDir(), "output")
	t.Setenv("GITHUB_OUTPUT", output)
	stdout, err := execute(t, "discover", "--config", "testdata/config.yaml", "--repository", "rancher/suse-security-policies")
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	wantCalls := []string{
		"gh api --hostname github.com --paginate --slurp repos/kubewarden/policies/releases",
		"gh api --hostname github.com --paginate --slurp repos/rancher/suse-security-policies/releases",
		tagsCall,
		"gh api --hostname github.com -H Accept: application/vnd.github.raw --allow-escape-sequences repos/kubewarden/policies/contents/policies/capabilities-psp-policy/metadata.yml?ref=capabilities-psp-policy%2Fv1.0.0",
		"gh api --hostname github.com -H Accept: application/vnd.github.raw --allow-escape-sequences repos/kubewarden/policies/contents/policies/pod-privileged-policy/metadata.yml?ref=pod-privileged-policy%2Fv1.10.0",
	}
	if !slices.Equal(f.calls, wantCalls) {
		t.Errorf("discover ran:\n%s\nexpected:\n%s", strings.Join(f.calls, "\n"), strings.Join(wantCalls, "\n"))
	}
	matrix := `[{"policy_id":"capabilities-psp","policy_name":"capabilities-psp-policy","tag":"capabilities-psp-policy/v1.0.0",` +
		`"upstream_release_url":"https://github.com/kubewarden/policies/releases/tag/capabilities-psp-policy/v1.0.0","version":"1.0.0"},` +
		`{"policy_id":"pod-privileged","policy_name":"pod-privileged-policy","tag":"pod-privileged-policy/v1.10.0",` +
		`"upstream_release_url":"https://github.com/kubewarden/policies/releases/tag/pod-privileged-policy/v1.10.0","version":"1.10.0"}]`
	if stdout != matrix+"\n" {
		t.Errorf("stdout is %q, expected %q", stdout, matrix+"\n")
	}
	got, err := os.ReadFile(output)
	if want := "matrix=" + matrix + "\ncount=2\n"; err != nil || string(got) != want {
		t.Errorf("GITHUB_OUTPUT holds %q (error: %v), expected %q", got, err, want)
	}
}

func TestDiscoverFilters(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantTags []string
		wantErr  string
		wantLog  string
	}{
		{name: "policy name", args: []string{"--policy-name", "pod-privileged-policy"}, wantTags: []string{"pod-privileged-policy/v1.10.0"}},
		{name: "older pinned version", args: []string{"--policy-name", "pod-privileged-policy", "--policy-version", "1.9.0"}, wantTags: []string{"pod-privileged-policy/v1.9.0"}},
		{name: "already released", args: []string{"--policy-name", "safe-labels-policy"}, wantTags: []string{}},
		{name: "pinned version already released", args: []string{"--policy-name", "safe-labels-policy", "--policy-version", "2.0.0"},
			wantTags: []string{"safe-labels-policy/v2.0.0"}, wantLog: "The repackage job verifies the published release"},
		{name: "prerelease version", args: []string{"--policy-name", "pod-privileged-policy", "--policy-version", "2.0.0"}, wantErr: "no upstream release matches"},
		{name: "version without name", args: []string{"--policy-version", "1.9.0"}, wantErr: "needs a policy name"},
		{name: "excluded policy", args: []string{"--policy-name", "sleeping-policy"}, wantErr: "excluded from publishing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newFake(t, "", discoverRules()...)
			var log strings.Builder
			logOut = &log
			stdout, err := execute(t, append([]string{"discover", "--config", "testdata/config.yaml", "--repository", "rancher/suse-security-policies"}, tt.args...)...)
			if !strings.Contains(log.String(), tt.wantLog) {
				t.Errorf("the log does not contain %q:\n%s", tt.wantLog, log.String())
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("discover returned the error %v, but the test expects an error with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("discover failed: %v", err)
			}
			var releases []map[string]string
			if err := json.Unmarshal([]byte(stdout), &releases); err != nil {
				t.Fatal(err)
			}
			var tags []string
			for _, r := range releases {
				tags = append(tags, r["tag"])
			}
			if !slices.Equal(tags, tt.wantTags) {
				t.Errorf("discover found %q, expected %q", tags, tt.wantTags)
			}
		})
	}
}

func TestDiscoverMissingMetadata(t *testing.T) {
	missing := rule{prefix: "gh api --hostname github.com -H Accept: application/vnd.github.raw --allow-escape-sequences repos/kubewarden/policies/contents/policies/capabilities-psp-policy/",
		err: "gh: Not Found (HTTP 404)"}
	tests := []struct {
		name, wantOut, wantErr string
		args                   []string
		rules                  []rule
		tries                  int
	}{
		{name: "missing file skips the release", rules: append([]rule{missing}, discoverRules()...), wantOut: "pod-privileged-policy/v1.10.0", tries: 1},
		{name: "missing file of the asked policy", args: []string{"--policy-name", "capabilities-psp-policy"},
			rules: append([]rule{missing}, discoverRules()...), wantErr: "HTTP 404", tries: 1},
		{name: "other error stops", rules: append([]rule{{prefix: missing.prefix, err: "gh: Server Error (HTTP 502)"}}, discoverRules()...), wantErr: "HTTP 502", tries: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "", tt.rules...)
			stdout, err := execute(t, append([]string{"discover", "--config", "testdata/config.yaml", "--repository", "rancher/suse-security-policies"}, tt.args...)...)
			if got := len(slices.DeleteFunc(slices.Clone(f.calls), func(c string) bool { return !strings.HasPrefix(c, missing.prefix) })); got != tt.tries {
				t.Errorf("discover read the missing file %d times instead of %d", got, tt.tries)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("discover returned the error %v, but the test expects an error with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || strings.Contains(stdout, "capabilities-psp") || !strings.Contains(stdout, tt.wantOut) {
				t.Errorf("discover returned %q (error: %v), expected only %q", stdout, err, tt.wantOut)
			}
		})
	}
}

func TestDiscoverTagWithoutRelease(t *testing.T) {
	burned := rule{prefix: tagsCall, out: `[[{"ref":"refs/tags/capabilities-psp-policy/v1.0.0"},{"ref":"refs/tags/pod-privileged-policy/v1.9.0"}]]`}
	tests := []struct {
		name, wantErr, wantLog string
		args                   []string
		rules                  []rule
		wantTags               []string
	}{
		{name: "full discovery skips the tag", rules: append([]rule{burned}, discoverRules()...), wantTags: []string{"pod-privileged-policy/v1.10.0"},
			wantLog: "::warning::skip capabilities-psp-policy/v1.0.0: the tag exists in rancher/suse-security-policies without a published release. A person must check the tag"},
		{name: "policy name stops", args: []string{"--policy-name", "capabilities-psp-policy"}, rules: append([]rule{burned}, discoverRules()...),
			wantErr: "capabilities-psp-policy/v1.0.0: the tag exists in rancher/suse-security-policies without a published release"},
		{name: "pinned version stops", args: []string{"--policy-name", "pod-privileged-policy", "--policy-version", "1.9.0"}, rules: append([]rule{burned}, discoverRules()...),
			wantErr: "pod-privileged-policy/v1.9.0: the tag exists"},
		{name: "tag list fails", rules: append([]rule{{prefix: tagsCall, err: "gh: Server Error (HTTP 502)"}}, discoverRules()...), wantErr: "HTTP 502"},
		{name: "no tags", rules: append([]rule{{prefix: tagsCall, out: "[[]]"}}, discoverRules()...),
			wantTags: []string{"capabilities-psp-policy/v1.0.0", "pod-privileged-policy/v1.10.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "", tt.rules...)
			var log strings.Builder
			logOut = &log
			stdout, err := execute(t, append([]string{"discover", "--config", "testdata/config.yaml", "--repository", "rancher/suse-security-policies"}, tt.args...)...)
			if !strings.Contains(log.String(), tt.wantLog) {
				t.Errorf("the log does not contain %q:\n%s", tt.wantLog, log.String())
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("discover returned the error %v, but the test expects an error with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("discover failed: %v", err)
			}
			var releases []map[string]string
			if err := json.Unmarshal([]byte(stdout), &releases); err != nil {
				t.Fatal(err)
			}
			var tags []string
			for _, r := range releases {
				tags = append(tags, r["tag"])
			}
			if !slices.Equal(tags, tt.wantTags) {
				t.Errorf("discover found %q, expected %q", tags, tt.wantTags)
			}
			if slices.ContainsFunc(f.calls, func(c string) bool { return strings.Contains(c, "capabilities-psp-policy%2Fv1.0.0") }) != slices.Contains(tt.wantTags, "capabilities-psp-policy/v1.0.0") {
				t.Errorf("discover read the metadata of a skipped tag, or did not read the metadata of a queued tag:\n%s", strings.Join(f.calls, "\n"))
			}
		})
	}
}

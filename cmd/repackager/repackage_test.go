package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var (
	testSHA        = strings.Repeat("0123456789", 4)
	testCommit     = strings.Repeat("c", 40)
	upstreamDigest = "sha256:" + strings.Repeat("a", 64)
	suseRef        = "ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:" + strings.Repeat("b", 64)
	spdxCheck      = "cosign verify-attestation " + suseRef + " --type spdxjson "
)

const (
	testTag   = "pod-privileged-policy/v1.2.3"
	ownRepo   = "gh api --hostname github.com repos/rancher/suse-security-policies/"
	ownList   = "gh api --hostname github.com --paginate --slurp repos/rancher/suse-security-policies/releases"
	destPull  = "kwctl pull registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3 "
	ownVerify = "cosign verify ghcr.io/rancher/"
	ownCreate = "gh api --hostname github.com -X POST repos/rancher/suse-security-policies/releases "
	ownUpload = "gh api --hostname github.com -X POST https://uploads.github.com/repos/rancher/suse-security-policies/releases/"
	ownAssets = "https://uploads.github.com/repos/rancher/suse-security-policies/releases/42/assets"
)

var assetNames = []string{suseWasmName, suseWasmBundleName, sourceArchiveName, suseSBOMName, suseSBOMBundleName, upstreamSBOMName, upstreamSBOMBundleName}

// created gives the response of GitHub to the creation of a draft release.
func created(id any, draft any, tag, uploadURL string) string {
	out, _ := json.Marshal(map[string]any{"id": id, "draft": draft, "tag_name": tag, "upload_url": uploadURL})
	return string(out)
}

// release gives the release that GitHub returns for the id, with the files of
// the work directory as its assets. If edit is not nil, it changes the release.
func release(id int, draft bool, edit func(rel map[string]any, assets []map[string]any)) func(work string) string {
	return func(work string) string {
		var assets []map[string]any
		for _, name := range assetNames {
			data, _ := os.ReadFile(filepath.Join(work, name))
			sum := sha256.Sum256(data)
			download := "https://github.com/rancher/suse-security-policies/releases/download/" + testTag + "/" + name
			if draft {
				download = "https://github.com/rancher/suse-security-policies/releases/download/untagged-1/" + name
			}
			assets = append(assets, map[string]any{"name": name, "size": len(data), "state": "uploaded",
				"digest": "sha256:" + hex.EncodeToString(sum[:]), "browser_download_url": download})
		}
		rel := map[string]any{"id": id, "draft": draft, "tag_name": testTag, "target_commitish": testSHA}
		if edit != nil {
			edit(rel, assets)
		}
		if _, ok := rel["assets"]; !ok {
			rel["assets"] = assets
		}
		out, _ := json.Marshal(rel)
		return string(out)
	}
}

// draftRead gives the draft that the check before the publication reads.
func draftRead(edit func(rel map[string]any, assets []map[string]any)) rule {
	return rule{prefix: ownRepo + "releases/42", fn: release(42, true, edit), once: true}
}

// attested gives the output of cosign verify-attestation for an SPDX
// attestation of the SBOM that the run wrote. If edit is not nil, it
// changes the SBOM before the attestation is made. An error gives an empty
// output, which the run reports as a different SBOM.
func attested(edit func(sbom map[string]any)) func(work string) string {
	return func(work string) string {
		var sbom map[string]any
		data, err := os.ReadFile(filepath.Join(work, suseSBOMName))
		if err != nil || json.Unmarshal(data, &sbom) != nil {
			return ""
		}
		if edit != nil {
			edit(sbom)
		}
		statement, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://spdx.dev/Document", "predicate": sbom})
		envelope, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(statement), "signatures": []any{}})
		return string(envelope) + "\n"
	}
}

// rerunRules describe a run after an earlier run that pushed and signed the
// module but did not publish the release.
func rerunRules() []rule {
	releaseURL := "https://github.com/kubewarden/policies/releases/tag/" + testTag
	upstreamMD := `rules: [{apiGroups: [""], operations: [CREATE]}]
mutating: false
annotations:
  io.kubewarden.kwctl: 1.20.0
  io.kubewarden.policy.author: Kubewarden developers
  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/pod-privileged
  io.kubewarden.policy.source: https://github.com/kubewarden/policies
  io.kubewarden.policy.version: 1.2.3
`
	repackagedMD := fmt.Sprintf(`rules: [{apiGroups: [""], operations: [CREATE]}]
mutating: false
annotations:
  io.kubewarden.kwctl: 1.21.0
  io.kubewarden.policy.author: "SUSE <containers@suse.com>"
  io.kubewarden.policy.ociUrl: ghcr.io/rancher/suse-security-policies/pod-privileged
  io.kubewarden.policy.source: https://github.com/kubewarden/policies
  io.kubewarden.policy.url: https://github.com/rancher/suse-security-policies
  io.kubewarden.policy.version: 1.2.3
  com.suse.policy.upstream.author: Kubewarden developers
  com.suse.policy.upstream.digest: %s
  com.suse.policy.upstream.release-url: %s
  com.suse.policy.upstream.repository: kubewarden/policies
  com.suse.policy.upstream.tag: %s
`, upstreamDigest, releaseURL, testTag)
	return []rule{
		{prefix: ownRepo + "releases/tags/", err: "gh: Not Found (HTTP 404)"},
		// The tag does not exist at the start or before the publication. The
		// publication creates it.
		{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)", once: true},
		{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)", once: true},
		{prefix: ownRepo + "git/ref/tags/", out: `{"object":{"type":"commit","sha":"` + testSHA + `"}}`},
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/releases/tags/", out: fmt.Sprintf(
			`{"tag_name":%q,"html_url":%q,"body":"Fix #12, thanks @alice","published_at":"2026-01-02T03:04:05Z"}`, testTag, releaseURL)},
		{prefix: "gh api --hostname github.com -H Accept: application/vnd.github.raw", out: "annotations:\n" +
			"  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/pod-privileged\n  io.kubewarden.policy.version: 1.2.3\n"},
		{prefix: "cosign verify ghcr.io/kubewarden/", out: `[{"critical":{"image":{"docker-manifest-digest":"` + upstreamDigest + `"}}}]`},
		{prefix: "kwctl pull registry://ghcr.io/kubewarden/", write: "upstream wasm"},
		{prefix: "kwctl inspect -o yaml $WORK/" + upstreamWasmName, out: upstreamMD},
		{prefix: "kwctl annotate ", write: "suse wasm"},
		{prefix: "kwctl inspect -o yaml $WORK/" + suseWasmName, out: repackagedMD},
		{prefix: "kwctl pull registry://ghcr.io/rancher/", write: "suse wasm"},
		{prefix: "kwctl digest ", out: "registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3@sha256:" + strings.Repeat("b", 64) + "\n"},
		{prefix: "gh release download " + testTag + " --repo github.com/kubewarden/policies --pattern " + upstreamSBOMAsset + " ", write: `{
  "documentNamespace": "https://kubewarden.io/spdx/pod-privileged-1.2.3",
  "documentDescribes": ["SPDXRef-Package-src"],
  "packages": [{"SPDXID": "SPDXRef-Package-src", "versionInfo": "` + testCommit + `", "licenseDeclared": "Apache-2.0"}]
}`},
		{prefix: "gh release download " + testTag + " --repo github.com/kubewarden/policies --pattern " + upstreamSBOMBundleAsset + " ", write: "bundle"},
		{prefix: "sbom-utility validate ", out: "valid"},
		// An annotated tag points at a tag object, which points at the commit.
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/ref/tags/", out: `{"object":{"type":"tag","sha":"` + strings.Repeat("d", 40) + `"}}`},
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", out: `{"object":{"type":"commit","sha":"` + testCommit + `"}}`},
		{prefix: "gh api --hostname github.com --allow-escape-sequences repos/kubewarden/policies/tarball/", out: "source archive"},
		{prefix: spdxCheck, fn: attested(nil)},
		{prefix: "cosign verify", out: "[]"},
		{prefix: "cosign sign", out: "", write: "bundle"},
		{prefix: "cosign attest", out: ""},
		{prefix: ownList, out: "[[]]", once: true},
		{prefix: ownCreate, out: created(42, true, testTag, ownAssets+"{?name,label}")},
		{prefix: ownUpload, out: "{}"},
		draftRead(nil),
		{prefix: ownRepo + "releases/42", fn: release(42, false, nil)},
		{prefix: "gh api --hostname github.com -X PATCH ", out: "{}"},
	}
}

// freshRules describe a run where the destination tag does not exist and
// no signature verifies.
func freshRules() []rule {
	return append([]rule{
		{prefix: destPull, err: "Error: manifest unknown"},
		{prefix: "kwctl push -o json ", out: `{"immutable_ref":"` + suseRef + `"}`},
		{prefix: ownVerify, err: "no signatures found", once: true},
		{prefix: "cosign verify-attestation ghcr.io/rancher/", err: "no attestations found", once: true},
		{prefix: "cosign verify-attestation ghcr.io/rancher/", err: "no attestations found", once: true},
	}, rerunRules()...)
}

// renamed gives the policy the id name_unknown, which looks like the OCI
// error code NAME_UNKNOWN.
func renamed(rules []rule) []rule {
	for i := range rules {
		for _, p := range []*string{&rules[i].prefix, &rules[i].out, &rules[i].write} {
			*p = strings.ReplaceAll(*p, "policies/pod-privileged", "policies/name_unknown")
		}
	}
	return rules
}

func TestRepackage(t *testing.T) {
	signOrPublish := []string{"kwctl push", "cosign sign --", "cosign attest", ownCreate, ownUpload, "-X PATCH", "-X DELETE"}
	noUpload := []string{ownUpload, "-X PATCH"}
	noPatch := []string{"-X PATCH"}
	var uploads []string
	for _, name := range assetNames {
		uploads = append(uploads, ownUpload+"42/assets?name="+name+" -H Content-Type: application/octet-stream --input $WORK/"+name+"\n")
	}
	draftCheck := "the check of the draft release " + testTag + " failed"
	afterCheck := "is published and immutable"
	otherDigest := "sha256:" + strings.Repeat("f", 64)
	// published gives the rules of a draft that passes its check, but changes
	// when it is published.
	published := func(edit func(rel map[string]any, assets []map[string]any)) []rule {
		return append([]rule{draftRead(nil), {prefix: ownRepo + "releases/42", fn: release(42, false, edit)}}, rerunRules()...)
	}
	tests := []struct {
		name    string
		dryRun  bool
		rules   []rule
		env     map[string]string // set after newFake
		wantErr string
		count   map[string]int    // the number of command lines that contain the key
		forbid  []string          // no command line may contain one of these
		want    []string          // each of these command lines must run
		before  map[string]string // a command line that contains the key must not run after the first one that contains the value
		// command lines that contain these strings run one after the other, with no other command between them
		sequence []string
		calls    int    // if not 0, the exact number of calls
		stdout   string // if not empty, stdout must contain it
		noCalls  bool   // no command may run
	}{
		{name: "dry run", dryRun: true, rules: freshRules(), forbid: append(signOrPublish, "cosign sign-blob")},
		{name: "dry run without a workflow ref", dryRun: true, rules: freshRules(), env: map[string]string{"GITHUB_WORKFLOW_REF": ""},
			forbid: append(signOrPublish, "cosign sign-blob")},
		{name: "no workflow ref", rules: freshRules(), env: map[string]string{"GITHUB_WORKFLOW_REF": ""},
			wantErr: "GITHUB_WORKFLOW_REF is not set", noCalls: true},
		{name: "workflow of another repository", rules: freshRules(),
			env:     map[string]string{"GITHUB_WORKFLOW_REF": "other/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main"},
			wantErr: "is not a workflow on the main branch of rancher/suse-security-policies", noCalls: true},
		{name: "workflow on another branch", rules: freshRules(),
			env:     map[string]string{"GITHUB_WORKFLOW_REF": "rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/feature"},
			wantErr: "is not a workflow on the main branch of rancher/suse-security-policies", noCalls: true},
		{name: "rerun", rules: rerunRules(), forbid: []string{"kwctl push", "cosign sign --", "cosign attest"},
			want: []string{ownCreate, "-X PATCH", "kwctl digest registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3",
				"kwctl pull registry://" + suseRef + " -o $WORK/existing-policy.wasm",
				"cosign verify " + suseRef + " --new-bundle-format=false --output json --certificate-identity https://github.com/rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com"}},
		{name: "destination pull denied", rules: append([]rule{{prefix: destPull, err: "Error: denied: permission denied"}}, rerunRules()...),
			wantErr: "cannot tell whether", forbid: signOrPublish},
		{name: "digest output without a digest", rules: append([]rule{
			{prefix: "kwctl digest ", out: "registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3\n"},
		}, rerunRules()...), wantErr: "has no sha256 digest", forbid: signOrPublish},
		// The error names the policy id, which must not count as NAME_UNKNOWN.
		{name: "policy id looks like an error code", rules: append([]rule{{
			prefix: "kwctl pull registry://ghcr.io/rancher/suse-security-policies/name_unknown:v1.2.3 ",
			err:    "Error: Registry error: url https://ghcr.io/v2/rancher/suse-security-policies/name_unknown/manifests/v1.2.3, envelope: OCI API errors: [OCI API error: denied]",
		}}, renamed(rerunRules())...), wantErr: "cannot tell whether", forbid: signOrPublish},
		{name: "already published", rules: append([]rule{{prefix: ownRepo + "releases/tags/", out: "{}"}}, rerunRules()...),
			wantErr: "is already published", calls: 1},
		{name: "tag without a release", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", out: "{}"}}, rerunRules()...),
			wantErr: "exists without a published release", calls: 2},
		{name: "tag lookup fails", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", err: "gh: Bad credentials (HTTP 401)"}}, rerunRules()...),
			wantErr: "HTTP 401", calls: 2},
		{name: "upstream tag lookup fails", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", err: "gh: Server Error (HTTP 502)"}}, freshRules()...),
			wantErr: "HTTP 502", forbid: []string{"cosign sign", "cosign attest", ownCreate, "/tarball/"}},
		{name: "upstream tag names another commit", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", out: `{"object":{"type":"commit","sha":"` + strings.Repeat("e", 40) + `"}}`}}, freshRules()...),
			wantErr: "the upstream SBOM records the commit", forbid: []string{"cosign sign", "cosign attest", ownCreate, "/tarball/"}},
		{name: "destination holds another module", rules: append([]rule{{prefix: "kwctl pull registry://ghcr.io/rancher/", write: "other wasm"}}, freshRules()[1:]...),
			wantErr: "holds another module", forbid: signOrPublish},
		{name: "stale draft", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7},{"tag_name":"other/v1.0.0","draft":true,"id":9}]]`, once: true},
			{prefix: "gh api --hostname github.com -X DELETE ", out: ""},
		}, rerunRules()...), want: []string{"gh api --hostname github.com -X DELETE repos/rancher/suse-security-policies/releases/7"},
			forbid: []string{"releases/9", "-X PATCH repos/rancher/suse-security-policies/releases/7"}},
		{name: "publish the created draft", rules: rerunRules(),
			want:   append([]string{"gh api --hostname github.com -X POST repos/rancher/suse-security-policies/releases -f tag_name=" + testTag + " -f target_commitish=" + testSHA + " -f name=" + testTag + " -F draft=true -f make_latest=false -F body=@$WORK/" + releaseNotesName + "\n"}, uploads...),
			count:  map[string]int{ownUpload + "42/assets?name=": 7, "-X PATCH repos/rancher/suse-security-policies/releases/42 -F draft=false -f make_latest=false": 1, "-X PATCH": 1},
			forbid: []string{"gh release create"}, before: map[string]string{ownUpload: "-X PATCH"},
			sequence: []string{"?name=" + upstreamSBOMBundleName + " ", ownRepo + "releases/tags/" + testTag, ownRepo + "git/ref/tags/" + testTag, ownRepo + "releases/42",
				"-X PATCH repos/rancher/suse-security-policies/releases/42 ", ownRepo + "releases/42", ownRepo + "git/ref/tags/" + testTag}},
		// Another draft with the tag exists, but only the draft that the run created is published.
		{name: "publish by the id in the creation response", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":42}]]`, once: true},
			{prefix: "gh api --hostname github.com -X DELETE ", out: ""},
			{prefix: ownCreate, out: created(43, true, testTag, strings.Replace(ownAssets, "/42/", "/43/", 1)+"{?name,label}")},
			{prefix: ownRepo + "releases/43", fn: release(43, true, nil), once: true},
			{prefix: ownRepo + "releases/43", fn: release(43, false, nil)},
		}, rerunRules()...), count: map[string]int{ownUpload + "43/assets?name=": 7, ownUpload + "42/": 0, ownRepo + "releases/42": 0,
			ownRepo + "releases/43": 2, "-X PATCH repos/rancher/suse-security-policies/releases/43 ": 1, "-X PATCH": 1}},
		{name: "draft misses an asset", rules: append([]rule{draftRead(func(rel map[string]any, assets []map[string]any) { rel["assets"] = assets[1:] })}, rerunRules()...),
			wantErr: `the asset "` + suseWasmName + `" is missing`, forbid: noPatch},
		{name: "draft has an extra asset", rules: append([]rule{draftRead(func(rel map[string]any, assets []map[string]any) {
			rel["assets"] = append(assets, map[string]any{"name": "extra.txt", "size": 1, "state": "uploaded", "digest": otherDigest})
		})}, rerunRules()...), wantErr: `the asset "extra.txt" is not expected`, forbid: noPatch},
		{name: "draft has an asset two times", rules: append([]rule{draftRead(func(rel map[string]any, assets []map[string]any) {
			rel["assets"] = append(assets, assets[0])
		})}, rerunRules()...), wantErr: "more than one time", forbid: noPatch},
		{name: "draft has a renamed asset", rules: append([]rule{draftRead(func(_ map[string]any, assets []map[string]any) { assets[0]["name"] = "suse-policy.1.wasm" })}, rerunRules()...),
			wantErr: `the asset "` + suseWasmName + `" is missing`, forbid: noPatch},
		{name: "draft asset has another digest", rules: append([]rule{draftRead(func(_ map[string]any, assets []map[string]any) { assets[2]["digest"] = otherDigest })}, rerunRules()...),
			wantErr: `the asset "` + sourceArchiveName + `" has the digest`, forbid: noPatch},
		{name: "draft asset has a null digest", rules: append([]rule{draftRead(func(_ map[string]any, assets []map[string]any) { assets[2]["digest"] = nil })}, rerunRules()...),
			wantErr: `the asset "` + sourceArchiveName + `" has the digest`, forbid: noPatch},
		{name: "draft asset has no digest", rules: append([]rule{draftRead(func(_ map[string]any, assets []map[string]any) { delete(assets[2], "digest") })}, rerunRules()...),
			wantErr: `the asset "` + sourceArchiveName + `" has the digest`, forbid: noPatch},
		{name: "draft asset is not uploaded", rules: append([]rule{draftRead(func(_ map[string]any, assets []map[string]any) { assets[3]["state"] = "open" })}, rerunRules()...),
			wantErr: `the asset "` + suseSBOMName + `" has the state open`, forbid: noPatch},
		{name: "draft asset has another size", rules: append([]rule{draftRead(func(_ map[string]any, assets []map[string]any) { assets[3]["size"] = 1 })}, rerunRules()...),
			wantErr: `the asset "` + suseSBOMName + `" has the size 1`, forbid: noPatch},
		{name: "draft has another commit", rules: append([]rule{draftRead(func(rel map[string]any, _ []map[string]any) { rel["target_commitish"] = "main" })}, rerunRules()...),
			wantErr: `target_commitish is "main"`, forbid: noPatch},
		{name: "draft is published", rules: append([]rule{draftRead(func(rel map[string]any, _ []map[string]any) { rel["draft"] = false })}, rerunRules()...),
			wantErr: "draft is false instead of true", forbid: noPatch},
		{name: "draft has another tag", rules: append([]rule{draftRead(func(rel map[string]any, _ []map[string]any) { rel["tag_name"] = "other/v1.2.3" })}, rerunRules()...),
			wantErr: `tag_name is "other/v1.2.3"`, forbid: noPatch},
		{name: "draft has another id", rules: append([]rule{draftRead(func(rel map[string]any, _ []map[string]any) { rel["id"] = 43 })}, rerunRules()...),
			wantErr: "the id is 43 instead of 42", forbid: noPatch},
		{name: "draft read fails", rules: append([]rule{{prefix: ownRepo + "releases/42", err: "gh: Server Error (HTTP 502)", once: true}}, rerunRules()...),
			wantErr: draftCheck, forbid: noPatch},
		{name: "release published before the publication", rules: append([]rule{
			{prefix: ownRepo + "releases/tags/", err: "gh: Not Found (HTTP 404)", once: true},
			{prefix: ownRepo + "releases/tags/", out: "{}"},
		}, rerunRules()...), wantErr: "is already published", forbid: append([]string{ownRepo + "releases/42"}, noPatch...),
			count: map[string]int{ownUpload: 7}},
		{name: "tag pushed before the publication", rules: append([]rule{
			{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)", once: true},
			{prefix: ownRepo + "git/ref/tags/", out: `{"object":{"type":"commit","sha":"` + strings.Repeat("e", 40) + `"}}`},
		}, rerunRules()...), wantErr: "the tag " + testTag + " exists", forbid: append([]string{ownRepo + "releases/42"}, noPatch...)},
		{name: "tag check before the publication fails", rules: append([]rule{
			{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)", once: true},
			{prefix: ownRepo + "git/ref/tags/", err: "gh: Server Error (HTTP 502)"},
		}, rerunRules()...), wantErr: draftCheck, forbid: noPatch},
		{name: "tag points at another commit after the publication", rules: append([]rule{
			{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)", once: true},
			{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)", once: true},
			{prefix: ownRepo + "git/ref/tags/", out: `{"object":{"type":"commit","sha":"` + strings.Repeat("e", 40) + `"}}`},
		}, rerunRules()...), wantErr: "points at the commit", count: map[string]int{"-X PATCH": 1}},
		{name: "release is still a draft after the publication", rules: published(func(rel map[string]any, _ []map[string]any) { rel["draft"] = true }),
			wantErr: "draft is true instead of false", count: map[string]int{"-X PATCH": 1}},
		{name: "asset replaced at the publication", rules: published(func(_ map[string]any, assets []map[string]any) { assets[0]["digest"] = otherDigest }),
			wantErr: afterCheck, count: map[string]int{"-X PATCH": 1}, stdout: "A check after the publication failed"},
		{name: "read after the publication fails", rules: append([]rule{draftRead(nil), {prefix: ownRepo + "releases/42", err: "gh: Server Error (HTTP 502)"}}, rerunRules()...),
			wantErr: afterCheck, count: map[string]int{"-X PATCH": 1}},
		{name: "published release has no download location", rules: published(func(_ map[string]any, assets []map[string]any) {
			assets[0]["browser_download_url"] = "https://github.com/rancher/suse-security-policies/releases/download/untagged-1/" + suseWasmName
		}), wantErr: "the downloadLocation recorded in the SBOM", count: map[string]int{"-X PATCH": 1}},
		{name: "created release is not a draft", rules: append([]rule{{prefix: ownCreate, out: created(42, false, testTag, ownAssets)}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "created release has another tag", rules: append([]rule{{prefix: ownCreate, out: created(42, true, "other/v1.2.3", ownAssets)}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "created release has no id", rules: append([]rule{{prefix: ownCreate, out: created(nil, true, testTag, ownAssets)}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "created release has a fractional id", rules: append([]rule{{prefix: ownCreate, out: created(42.5, true, testTag, ownAssets)}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "created release has a string id", rules: append([]rule{{prefix: ownCreate, out: created("42", true, testTag, ownAssets)}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "created release has a zero id", rules: append([]rule{{prefix: ownCreate, out: created(0, true, testTag, "https://uploads.github.com/repos/rancher/suse-security-policies/releases/0/assets")}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "created release has a negative id", rules: append([]rule{{prefix: ownCreate, out: created(-42, true, testTag, "https://uploads.github.com/repos/rancher/suse-security-policies/releases/-42/assets")}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		// JSON numbers are float64, which cannot hold every integer above 2^53.
		{name: "created release has an id above 2^53", rules: append([]rule{{prefix: ownCreate, out: created(float64(1<<53)+2, true, testTag, "https://uploads.github.com/repos/rancher/suse-security-policies/releases/9007199254740994/assets")}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "upload URL of another repository", rules: append([]rule{{prefix: ownCreate, out: created(42, true, testTag, "https://uploads.github.com/repos/other/suse-security-policies/releases/42/assets{?name,label}")}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "upload URL of another release", rules: append([]rule{{prefix: ownCreate, out: created(42, true, testTag, strings.Replace(ownAssets, "/42/", "/43/", 1))}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "upload URL of another host", rules: append([]rule{{prefix: ownCreate, out: created(42, true, testTag, strings.Replace(ownAssets, "uploads.github.com", "uploads.example.com", 1))}}, rerunRules()...),
			wantErr: "not as expected", forbid: noUpload},
		{name: "creation fails", rules: append([]rule{{prefix: ownCreate, err: "gh: Validation Failed (HTTP 422)"}}, rerunRules()...),
			wantErr: "HTTP 422", forbid: noUpload},
		{name: "upload fails", rules: append([]rule{{prefix: ownUpload + "42/assets?name=" + sourceArchiveName + " ", err: "gh: Server Error (HTTP 502)"}}, rerunRules()...),
			wantErr: "cannot upload " + sourceArchiveName, forbid: []string{"-X PATCH", "?name=" + suseSBOMName + " "}},
		{name: "publication fails", rules: append([]rule{{prefix: "gh api --hostname github.com -X PATCH ", err: "gh: Server Error (HTTP 502)"}}, rerunRules()...),
			wantErr: "HTTP 502", count: map[string]int{ownUpload + "42/assets?name=": 7, "-X PATCH": 1}},
		// An earlier run attested an SBOM with another tool name.
		{name: "stale SBOM attestation", rules: append([]rule{{prefix: spdxCheck, fn: attested(func(sbom map[string]any) {
			sbom["creationInfo"].(map[string]any)["creators"] = []any{"Organization: SUSE", "Tool: suse-security-policies-" + testSHA}
		})}}, rerunRules()...), wantErr: "differs from the release SBOM",
			forbid: []string{"cosign sign", "cosign attest", ownCreate, ownUpload, "-X PATCH", "-X DELETE"}},
		{name: "published release in the list", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":false,"id":8}]]`, once: true},
		}, rerunRules()...), wantErr: "is already published", forbid: []string{"-X DELETE", ownCreate, ownUpload}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			work := t.TempDir()
			f := newFake(t, work, tt.rules...)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			args := []string{"repackage", "--config", "testdata/config.yaml", "--repository", "rancher/suse-security-policies", "--sha", testSHA,
				"--policy-name", "pod-privileged-policy", "--policy-version", "1.2.3", "--work-dir", work}
			if tt.dryRun {
				args = append(args, "--dry-run")
			}
			stdout, err := execute(t, args...)
			if !strings.Contains(stdout, tt.stdout) {
				t.Errorf("stdout does not contain %q:\n%s", tt.stdout, stdout)
			}
			if tt.wantErr == "" && err != nil {
				t.Fatalf("repackage failed: %v", err)
			} else if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("repackage returned the error %v, but the test expects an error with %q", err, tt.wantErr)
			}
			if tt.noCalls && len(f.calls) != 0 {
				t.Errorf("repackage ran %d commands instead of none:\n%s", len(f.calls), strings.Join(f.calls, "\n"))
			}
			if tt.calls != 0 && len(f.calls) != tt.calls {
				t.Errorf("repackage ran %d commands instead of %d:\n%s", len(f.calls), tt.calls, strings.Join(f.calls, "\n"))
			}
			for _, call := range f.calls {
				for _, s := range tt.forbid {
					if strings.Contains(call, s) {
						t.Errorf("the command %q must not run", call)
					}
				}
			}
			for _, w := range tt.want {
				if !strings.Contains(strings.Join(f.calls, "\n")+"\n", w) {
					t.Errorf("no command contains %q", w)
				}
			}
			for later, first := range tt.before {
				i := slices.IndexFunc(f.calls, func(call string) bool { return strings.Contains(call, first) })
				if i < 0 {
					t.Errorf("no command contains %q", first)
					continue
				}
				for _, call := range f.calls[i+1:] {
					if strings.Contains(call, later) {
						t.Errorf("the command %q runs after the first command that contains %q", call, first)
					}
				}
			}
			if len(tt.sequence) > 0 {
				found := false
				for i := 0; i+len(tt.sequence) <= len(f.calls) && !found; i++ {
					found = true
					for k, s := range tt.sequence {
						found = found && strings.Contains(f.calls[i+k], s)
					}
				}
				if !found {
					t.Errorf("the commands %q do not run one after the other:\n%s", tt.sequence, strings.Join(f.calls, "\n"))
				}
			}
			for s, want := range tt.count {
				got := 0
				for _, call := range f.calls {
					if strings.Contains(call, s) {
						got++
					}
				}
				if got != want {
					t.Errorf("%d commands contain %q instead of %d:\n%s", got, s, want, strings.Join(f.calls, "\n"))
				}
			}
		})
	}
}

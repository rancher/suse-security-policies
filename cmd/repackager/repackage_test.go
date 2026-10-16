package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// realRun is the run of helpers.go, before newFake replaces it.
var realRun = run

var (
	testSHA        = strings.Repeat("0123456789", 4)
	testCommit     = strings.Repeat("c", 40)
	upstreamDigest = "sha256:" + strings.Repeat("a", 64)
	suseRef        = "ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:" + strings.Repeat("b", 64)
	spdxCheck      = "cosign verify-attestation " + suseRef + " --type spdxjson "
	signCheck      = "cosign verify-attestation " + suseRef + " --type " + signaturePredicateType + " "
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
		return envelope(sbom)
	}
}

func envelope(sbom any) string {
	statement, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://spdx.dev/Document", "predicate": sbom})
	out, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(statement), "signatures": []any{}})
	return string(out) + "\n"
}

// publishedSHA is the commit of an earlier run, which is not testSHA.
var publishedSHA = strings.Repeat("9", 40)

// publishedFiles gives the assets of a published release. If editSBOM is not
// nil, it changes the SUSE SBOM and its package.
func publishedFiles(editSBOM func(doc, pkg map[string]any)) map[string]string {
	wasm := "suse wasm"
	sum := sha256.Sum256([]byte(wasm))
	upstreamSBOM := `{"documentNamespace":"https://kubewarden.io/spdx/pod-privileged-1.2.3"}`
	upstreamSum := sha256.Sum256([]byte(upstreamSBOM))
	pkg := map[string]any{"SPDXID": "SPDXRef-Package-pod-privileged", "checksums": []any{map[string]any{"algorithm": "SHA256", "checksumValue": hex.EncodeToString(sum[:])}},
		"externalRefs": []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
			"referenceLocator": "pkg:oci/pod-privileged@sha256%3A" + strings.Repeat("b", 64) + "?repository_url=ghcr.io/rancher/suse-security-policies/pod-privileged&tag=v1.2.3"}}}
	doc := map[string]any{"SPDXID": "SPDXRef-DOCUMENT", "packages": []any{pkg}, "externalDocumentRefs": []any{map[string]any{"externalDocumentId": "DocumentRef-upstream",
		"spdxDocument": "https://kubewarden.io/spdx/pod-privileged-1.2.3", "checksum": map[string]any{"algorithm": "SHA256", "checksumValue": hex.EncodeToString(upstreamSum[:])}}}}
	if editSBOM != nil {
		editSBOM(doc, pkg)
	}
	sbom, _ := json.Marshal(doc)
	return map[string]string{suseWasmName: wasm, suseWasmBundleName: "wasm bundle", sourceArchiveName: "source archive", suseSBOMName: string(sbom),
		suseSBOMBundleName: "sbom bundle", upstreamSBOMName: upstreamSBOM, upstreamSBOMBundleName: "upstream bundle"}
}

// publishedRelease gives the published release with files as its assets. If
// edit is not nil, it changes the release.
func publishedRelease(files map[string]string, edit func(rel map[string]any, assets []map[string]any)) string {
	var assets []map[string]any
	for _, name := range assetNames {
		sum := sha256.Sum256([]byte(files[name]))
		assets = append(assets, map[string]any{"name": name, "size": len(files[name]), "state": "uploaded", "digest": "sha256:" + hex.EncodeToString(sum[:])})
	}
	rel := map[string]any{"id": 42, "draft": false, "tag_name": testTag, "target_commitish": publishedSHA}
	if edit != nil {
		edit(rel, assets)
	}
	if _, ok := rel["assets"]; !ok {
		rel["assets"] = assets
	}
	out, _ := json.Marshal(rel)
	return string(out)
}

// publishedRules describe a run for a release that an earlier run published.
func publishedRules(editSBOM func(doc, pkg map[string]any)) []rule {
	files := publishedFiles(editSBOM)
	var sbom any
	_ = json.Unmarshal([]byte(files[suseSBOMName]), &sbom)
	rules := []rule{
		{prefix: ownRepo + "releases/tags/", out: publishedRelease(files, nil)},
		{prefix: ownRepo + "git/ref/tags/", out: `{"object":{"type":"commit","sha":"` + publishedSHA + `"}}`},
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/releases/tags/", out: fmt.Sprintf(`{"tag_name":%q,"html_url":"https://github.com/kubewarden/policies/releases/tag/%s"}`, testTag, testTag)},
		{prefix: "gh api --hostname github.com -H Accept: application/vnd.github.raw", out: "annotations:\n" +
			"  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/pod-privileged\n  io.kubewarden.policy.version: 1.2.3\n"},
		{prefix: "cosign verify-blob ", out: ""},
		{prefix: "kwctl digest registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3", out: "registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3@sha256:" + strings.Repeat("b", 64) + "\n"},
		{prefix: "kwctl pull registry://" + suseRef + " -o $WORK/published/" + registryWasmName, write: files[suseWasmName]},
		{prefix: spdxCheck, out: envelope(sbom)},
		{prefix: signCheck, out: ""},
		{prefix: ownVerify, out: "[]"},
	}
	for _, name := range assetNames {
		rules = append(rules, rule{prefix: publishedDownload(name), write: files[name]})
	}
	return rules
}

func publishedDownload(name string) string {
	return "gh release download " + testTag + " --repo github.com/rancher/suse-security-policies --pattern " + name + " --output $WORK/published/" + name + " --clobber"
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
  org.opencontainers.image.source: https://github.com/rancher/suse-security-policies
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

// The errors of cosign v3.1.3 when nothing verifies, or when a check fails
// for another reason. cobra prints the error, and then main logs it.
const (
	noSignatures   = "Error: no signatures found\n2026/01/02 03:04:05 error during command execution: no signatures found"
	noAttestations = "Error: no matching attestations: \n2026/01/02 03:04:05 error during command execution: no matching attestations: "
	noSignatureAtt = "Error: none of the attestations matched the predicate type: " + signaturePredicateType + ", found: https://spdx.dev/Document\n" +
		"2026/01/02 03:04:05 error during command execution: none of the attestations matched the predicate type: " + signaturePredicateType + ", found: https://spdx.dev/Document"
	noSPDXAtt = "Error: none of the attestations matched the predicate type: https://spdx.dev/Document, found: " + signaturePredicateType + "\n" +
		"2026/01/02 03:04:05 error during command execution: none of the attestations matched the predicate type: https://spdx.dev/Document, found: " + signaturePredicateType
	timeout = "Error: Get \"https://ghcr.io/v2/\": dial tcp: i/o timeout\n2026/01/02 03:04:05 error during command execution: Get \"https://ghcr.io/v2/\": dial tcp: i/o timeout"
	badGate = "Error: GET https://ghcr.io/v2/rancher/suse-security-policies/pod-privileged/manifests/sha256-b.sig: unexpected status code 502 Bad Gateway"
	tooMany = "Error: GET https://ghcr.io/v2/rancher/suse-security-policies/pod-privileged/referrers/sha256:b: TOOMANYREQUESTS: retry later"
)

// freshRules describe a run where the destination tag does not exist and
// no signature verifies.
func freshRules() []rule {
	return append([]rule{
		{prefix: destPull, err: "Error: manifest unknown"},
		{prefix: "kwctl push -o json ", out: `{"immutable_ref":"` + suseRef + `"}`},
		{prefix: ownVerify, err: noSignatures, exit: 10, once: true},
		{prefix: "cosign verify-attestation ghcr.io/rancher/", err: noAttestations, exit: 1, once: true},
		{prefix: "cosign verify-attestation ghcr.io/rancher/", err: noAttestations, exit: 1, once: true},
	}, rerunRules()...)
}

// joined gives the outputs of fns one after the other.
func joined(fns ...func(work string) string) func(work string) string {
	return func(work string) string {
		var out string
		for _, fn := range fns {
			out += fn(work)
		}
		return out
	}
}

// thrice gives a rule for each of the three tries of a read.
func thrice(r rule) []rule {
	r.once = true
	return []rule{r, r, r}
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
	cleanupFailed := "cannot delete one or more old drafts for the tag"
	deleteCmd := "gh api --hostname github.com -X DELETE "
	notFound := "gh: Not Found (HTTP 404)"
	// oldDraft gives the rules for a list after the publication that shows the
	// old draft 7. The parameter draft is the state of release 7 at the second read.
	oldDraft := func(draft bool) []rule {
		return []rule{{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7}]]`, once: true},
			{prefix: ownRepo + "releases/7", fn: release(7, draft, nil)}}
	}
	otherDigest := "sha256:" + strings.Repeat("f", 64)
	// An earlier run attested an SBOM with another tool name.
	staleSBOM := func(sbom map[string]any) {
		sbom["creationInfo"].(map[string]any)["creators"] = []any{"Organization: SUSE", "Tool: suse-security-policies-" + testSHA}
	}
	staleErr := "differ from the release SBOM"
	publishedWrites := []string{"-X ", "kwctl push", "cosign sign", "cosign attest", "gh release upload", "gh release create", "gh release edit", "gh release delete"}
	var publishedDownloads []string
	notRecorded := func(asset string) string {
		sum := sha256.Sum256([]byte(publishedFiles(nil)[asset]))
		return "does not record the SHA256 checksum " + hex.EncodeToString(sum[:]) + ` of the asset "` + asset + `"`
	}
	for _, name := range assetNames {
		publishedDownloads = append(publishedDownloads, publishedDownload(name))
	}
	noWrite := []string{"cosign sign", "cosign attest", ownCreate, ownUpload, "-X PATCH", "-X DELETE"}
	// published gives the rules of a draft that passes its check, but changes
	// when it is published.
	published := func(edit func(rel map[string]any, assets []map[string]any)) []rule {
		return append([]rule{draftRead(nil), {prefix: ownRepo + "releases/42", fn: release(42, false, edit)}}, rerunRules()...)
	}
	// repackagedSource gives the rules of a rerun where the line of
	// org.opencontainers.image.source in the repackaged metadata is line.
	repackagedSource := func(line string) []rule {
		rules := rerunRules()
		for i, r := range rules {
			if r.prefix == "kwctl inspect -o yaml $WORK/"+suseWasmName {
				rules[i].out = strings.Replace(r.out, "  org.opencontainers.image.source: https://github.com/rancher/suse-security-policies\n", line, 1)
			}
		}
		return rules
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
		calls    int             // if not 0, the exact number of calls
		waits    []time.Duration // if not nil, the exact waits before the retries
		stdout   string          // if not empty, stdout must contain it
		noStdout string          // if not empty, stdout must not contain it
		noCalls  bool            // no command may run
	}{
		{name: "dry run", dryRun: true, rules: freshRules(), forbid: append(signOrPublish, "cosign sign-blob"),
			count: map[string]int{"sbom-utility validate --input-file $WORK/" + draftSUSESBOMName: 1, "sbom-utility validate": 1}},
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
		{name: "repackaged module names another source", rules: repackagedSource("  org.opencontainers.image.source: https://github.com/kubewarden/policies\n"),
			wantErr: `the repackaged policy has org.opencontainers.image.source="https://github.com/kubewarden/policies"`, forbid: append(signOrPublish, destPull)},
		{name: "repackaged module has no source", rules: repackagedSource(""),
			wantErr: `the repackaged policy has org.opencontainers.image.source=""`, forbid: append(signOrPublish, destPull)},
		{name: "destination pull denied", rules: append([]rule{{prefix: destPull, err: "Error: denied: permission denied"}}, rerunRules()...),
			wantErr: "cannot tell whether", forbid: signOrPublish, count: map[string]int{destPull: 3}},
		{name: "digest output without a digest", rules: append([]rule{
			{prefix: "kwctl digest ", out: "registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3\n"},
		}, rerunRules()...), wantErr: "has no sha256 digest", forbid: signOrPublish},
		// The error names the policy id, which must not count as NAME_UNKNOWN.
		{name: "policy id looks like an error code", rules: append([]rule{{
			prefix: "kwctl pull registry://ghcr.io/rancher/suse-security-policies/name_unknown:v1.2.3 ",
			err:    "Error: Registry error: url https://ghcr.io/v2/rancher/suse-security-policies/name_unknown/manifests/v1.2.3, envelope: OCI API errors: [OCI API error: denied]",
		}}, renamed(rerunRules())...), wantErr: "cannot tell whether", forbid: signOrPublish,
			count: map[string]int{"kwctl pull registry://ghcr.io/rancher/suse-security-policies/name_unknown:v1.2.3 ": 3}},
		{name: "policy id looks like an error code in a short error", rules: append([]rule{{
			prefix: "kwctl pull registry://ghcr.io/rancher/suse-security-policies/name_unknown:v1.2.3 ",
			err:    "Error: GET https://ghcr.io/v2/rancher/suse-security-policies/name_unknown/manifests/v1.2.3: unexpected status code 502 Bad Gateway", once: true,
		}}, renamed(rerunRules())...), want: []string{"-X PATCH"}, forbid: []string{"kwctl push"},
			count: map[string]int{"kwctl pull registry://ghcr.io/rancher/suse-security-policies/name_unknown:v1.2.3 ": 2}, waits: []time.Duration{2 * time.Second}},
		{name: "published release verifies", rules: publishedRules(nil), forbid: publishedWrites, stdout: "### Verified the published release " + testTag,
			want: append([]string{
				"cosign verify-blob $WORK/published/" + suseWasmName + " --bundle $WORK/published/" + suseWasmBundleName + " --certificate-identity https://github.com/rancher/",
				"cosign verify-blob $WORK/published/" + suseSBOMName + " --bundle $WORK/published/" + suseSBOMBundleName + " --certificate-identity https://github.com/rancher/",
				"cosign verify-blob $WORK/published/" + upstreamSBOMName + " --bundle $WORK/published/" + upstreamSBOMBundleName + " --certificate-identity https://github.com/kubewarden/",
				"cosign verify " + suseRef + " --new-bundle-format=false ", signCheck, spdxCheck, ownRepo + "git/ref/tags/" + testTag,
			}, publishedDownloads...)},
		{name: "dry run of a published release", dryRun: true, rules: publishedRules(nil), forbid: publishedWrites, stdout: "### Verified the published release " + testTag},
		{name: "dry run of a published release without a workflow ref", dryRun: true, rules: publishedRules(nil), env: map[string]string{"GITHUB_WORKFLOW_REF": ""},
			wantErr: "the run needs GITHUB_WORKFLOW_REF to verify the published release", forbid: append(publishedWrites, "gh release download", "cosign", "kwctl")},
		{name: "published release misses an asset", rules: append([]rule{
			{prefix: ownRepo + "releases/tags/", out: publishedRelease(publishedFiles(nil), func(rel map[string]any, assets []map[string]any) { rel["assets"] = slices.Delete(assets, 2, 3) })},
			{prefix: publishedDownload(sourceArchiveName), err: "no assets match the file pattern", exit: 1},
		}, publishedRules(nil)...), wantErr: afterCheck, forbid: publishedWrites, stdout: `the asset "` + sourceArchiveName + `" is missing`},
		{name: "published asset has another digest", rules: append([]rule{{prefix: publishedDownload(sourceArchiveName), write: "other archive"}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: `the asset "` + sourceArchiveName + `" has the digest`},
		{name: "published wasm signature does not verify", rules: append([]rule{{prefix: "cosign verify-blob $WORK/published/" + suseWasmName + " ", err: "Error: invalid signature", exit: 1}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: `the signature of the asset "` + suseWasmName + `" does not verify`},
		{name: "registry holds another module than the release", rules: append([]rule{{prefix: "kwctl pull registry://" + suseRef, write: "other wasm"}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: "holds a module with sha256"},
		{name: "SBOM attestation differs from the published SBOM", rules: append([]rule{{prefix: spdxCheck, out: envelope(map[string]any{"SPDXID": "SPDXRef-DOCUMENT"})}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: staleErr},
		{name: "tag of the published release points at another commit", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", out: `{"object":{"type":"commit","sha":"` + testSHA + `"}}`}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: "points at the commit"},
		{name: "published SBOM names another digest", rules: publishedRules(func(_, pkg map[string]any) {
			pkg["externalRefs"] = []any{map[string]any{"referenceType": "purl", "referenceLocator": "pkg:oci/pod-privileged@sha256%3A" + strings.Repeat("f", 64)}}
		}), wantErr: afterCheck, forbid: publishedWrites, stdout: "does not name the digest"},
		{name: "published SBOM records another module checksum", rules: publishedRules(func(_, pkg map[string]any) {
			pkg["checksums"] = []any{map[string]any{"algorithm": "SHA256", "checksumValue": strings.Repeat("f", 64)}}
		}), wantErr: afterCheck, forbid: publishedWrites, stdout: notRecorded(suseWasmName)},
		{name: "published SBOM records another upstream SBOM checksum", rules: publishedRules(func(doc, _ map[string]any) {
			doc["externalDocumentRefs"].([]any)[0].(map[string]any)["checksum"] = map[string]any{"algorithm": "SHA256", "checksumValue": strings.Repeat("f", 64)}
		}), wantErr: afterCheck, forbid: publishedWrites, stdout: notRecorded(upstreamSBOMName)},
		{name: "published upstream SBOM signature does not verify", rules: append([]rule{{prefix: "cosign verify-blob $WORK/published/" + upstreamSBOMName + " ", err: "Error: invalid signature", exit: 1}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: `the signature of the asset "` + upstreamSBOMName + `" does not verify`},
		{name: "legacy signature of the published module does not verify", rules: append([]rule{{prefix: ownVerify, err: "Error: no matching signatures: invalid signature", exit: 1}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: publishedWrites, stdout: "no matching signatures"},
		{name: "digest of the published module fails", rules: append([]rule{{prefix: "kwctl digest ", err: "Error: denied: permission denied"}}, publishedRules(nil)...),
			wantErr: afterCheck, forbid: append(publishedWrites, "kwctl pull", ownVerify, signCheck, spdxCheck), stdout: "permission denied"},
		{name: "tag without a release", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", out: "{}"}}, rerunRules()...),
			wantErr: "exists without a published release", calls: 2},
		{name: "tag lookup fails", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", err: "gh: Bad credentials (HTTP 401)"}}, rerunRules()...),
			wantErr: "HTTP 401", calls: 2},
		{name: "upstream tag lookup fails", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", err: "gh: Server Error (HTTP 502)"}}, freshRules()...),
			wantErr: "HTTP 502", forbid: append(signOrPublish, "/tarball/", destPull), count: map[string]int{"repos/kubewarden/policies/git/tags/": 3},
			waits: []time.Duration{2 * time.Second, 8 * time.Second}},
		{name: "upstream tag names another commit", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", out: `{"object":{"type":"commit","sha":"` + strings.Repeat("e", 40) + `"}}`}}, freshRules()...),
			wantErr: "the upstream SBOM records the commit", forbid: append(signOrPublish, "/tarball/", destPull)},
		{name: "upstream SBOM signature does not verify", rules: append([]rule{{prefix: "cosign verify-blob $WORK/" + upstreamSBOMName + " ", err: "Error: invalid signature", exit: 1}}, freshRules()...),
			wantErr: "invalid signature", forbid: append(signOrPublish, "/tarball/", destPull), count: map[string]int{"cosign verify-blob": 3}},
		{name: "upstream SBOM is missing", rules: append([]rule{{prefix: "gh release download " + testTag + " --repo github.com/kubewarden/policies --pattern " + upstreamSBOMAsset + " ", err: "no assets match the file pattern", exit: 1}}, freshRules()...),
			wantErr: "no assets match the file pattern", forbid: append(signOrPublish, destPull), count: map[string]int{"gh release download": 1}},
		{name: "upstream checks before the push", rules: freshRules(), want: []string{"kwctl push"},
			before: map[string]string{"gh release download ": destPull, "repos/kubewarden/policies/git/": destPull, "/tarball/": destPull, draftSUSESBOMName: destPull}},
		{name: "SUSE SBOM not valid", rules: append([]rule{{prefix: "sbom-utility validate ", out: "the license is not valid", err: "sbom-utility: exit status 1"}}, freshRules()...),
			wantErr: "the SUSE SBOM is not valid SPDX 2.3", forbid: append(signOrPublish, destPull), count: map[string]int{"sbom-utility validate": 1}},
		{name: "upstream release without a publication time", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/releases/tags/",
			out: fmt.Sprintf(`{"tag_name":%q,"html_url":"https://github.com/kubewarden/policies/releases/tag/%s"}`, testTag, testTag)}}, freshRules()...),
			wantErr: "has no publication time", forbid: append(signOrPublish, destPull, "sbom-utility")},
		{name: "destination holds another module", rules: append([]rule{{prefix: "kwctl pull registry://ghcr.io/rancher/", write: "other wasm"}}, freshRules()[1:]...),
			wantErr: "holds another module", forbid: signOrPublish},
		{name: "stale draft", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7},{"tag_name":"other/v1.0.0","draft":true,"id":9}]]`, once: true},
			{prefix: ownRepo + "releases/7", fn: release(7, true, nil)},
			{prefix: deleteCmd, out: ""},
		}, rerunRules()...), want: []string{deleteCmd + "repos/rancher/suse-security-policies/releases/7"},
			forbid: []string{"releases/9", "-X PATCH repos/rancher/suse-security-policies/releases/7"},
			before: map[string]string{"-X PATCH": deleteCmd, ownList: ownRepo + "releases/7", ownRepo + "releases/7": deleteCmd}},
		{name: "old draft published before the second read", rules: append(oldDraft(false), rerunRules()...),
			want: []string{ownRepo + "releases/7"}, forbid: []string{deleteCmd}},
		{name: "own release in the list after the publication", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":42}]]`, once: true},
		}, rerunRules()...), want: []string{ownList}, forbid: []string{deleteCmd}, count: map[string]int{ownRepo + "releases/42": 2}},
		{name: "old draft moved to another tag before the second read", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7}]]`, once: true},
			{prefix: ownRepo + "releases/7", fn: release(7, true, func(rel map[string]any, _ []map[string]any) { rel["tag_name"] = "other/v1.0.0" })},
		}, rerunRules()...), want: []string{ownRepo + "releases/7"}, forbid: []string{deleteCmd}, noStdout: cleanupFailed},
		{name: "second read of an old draft fails", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7}]]`, once: true},
			{prefix: ownRepo + "releases/7", err: "gh: Server Error (HTTP 502)"},
		}, rerunRules()...), want: []string{ownRepo + "releases/7"}, forbid: []string{deleteCmd}, stdout: cleanupFailed},
		{name: "old draft gone before the second read", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7}]]`, once: true},
			{prefix: ownRepo + "releases/7", err: notFound},
		}, rerunRules()...), want: []string{ownRepo + "releases/7"}, forbid: []string{deleteCmd}, noStdout: cleanupFailed},
		{name: "old draft gone before the deletion", rules: append(append(oldDraft(true), rule{prefix: deleteCmd, err: notFound}), rerunRules()...),
			want: []string{deleteCmd + "repos/rancher/suse-security-policies/releases/7"}, noStdout: cleanupFailed},
		{name: "list after the publication with a string id and a published release", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":"7"},{"tag_name":"` + testTag + `","draft":false,"id":8}]]`, once: true},
		}, rerunRules()...), want: []string{ownList}, forbid: []string{deleteCmd, "releases/7", "releases/8"}, noStdout: cleanupFailed},
		{name: "deletion of an old draft fails", rules: append(append(oldDraft(true), rule{prefix: deleteCmd, err: "gh: Server Error (HTTP 502)"}), rerunRules()...),
			count: map[string]int{deleteCmd + "repos/rancher/suse-security-policies/releases/7": 1}, stdout: cleanupFailed, waits: []time.Duration{}},
		{name: "list after the publication fails", rules: append(thrice(rule{prefix: ownList, err: "gh: Server Error (HTTP 502)"}), rerunRules()...),
			count: map[string]int{ownList: 3}, forbid: []string{deleteCmd}, stdout: cleanupFailed},
		{name: "no deletion after a failed check", rules: append(append(oldDraft(true), rule{prefix: deleteCmd, out: ""}),
			published(func(_ map[string]any, assets []map[string]any) { assets[0]["digest"] = otherDigest })...),
			wantErr: afterCheck, forbid: []string{ownList, deleteCmd, ownRepo + "releases/7"}},
		{name: "publish the created draft", rules: rerunRules(),
			want:   append([]string{"gh api --hostname github.com -X POST repos/rancher/suse-security-policies/releases -f tag_name=" + testTag + " -f target_commitish=" + testSHA + " -f name=" + testTag + " -F draft=true -f make_latest=false -F body=@$WORK/" + releaseNotesName + "\n"}, uploads...),
			count:  map[string]int{ownUpload + "42/assets?name=": 7, "-X PATCH repos/rancher/suse-security-policies/releases/42 -F draft=false -f make_latest=false": 1, "-X PATCH": 1},
			forbid: []string{"gh release create", deleteCmd}, before: map[string]string{ownUpload: "-X PATCH", "-X PATCH": ownList},
			sequence: []string{"?name=" + upstreamSBOMBundleName + " ", ownRepo + "releases/tags/" + testTag, ownRepo + "git/ref/tags/" + testTag, ownRepo + "releases/42",
				"-X PATCH repos/rancher/suse-security-policies/releases/42 ", ownRepo + "releases/42", ownRepo + "git/ref/tags/" + testTag}},
		// Another draft with the tag exists, but only the draft that the run
		// created is published. The run deletes the other draft after the publication.
		{name: "publish by the id in the creation response", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":42},{"tag_name":"` + testTag + `","draft":true,"id":43}]]`, once: true},
			{prefix: deleteCmd, out: ""},
			{prefix: ownCreate, out: created(43, true, testTag, strings.Replace(ownAssets, "/42/", "/43/", 1)+"{?name,label}")},
			{prefix: ownRepo + "releases/42", fn: release(42, true, nil)},
			{prefix: ownRepo + "releases/43", fn: release(43, true, nil), once: true},
			{prefix: ownRepo + "releases/43", fn: release(43, false, nil)},
		}, rerunRules()...), count: map[string]int{ownUpload + "43/assets?name=": 7, ownUpload + "42/": 0, ownRepo + "releases/42": 1,
			ownRepo + "releases/43": 2, "-X PATCH repos/rancher/suse-security-policies/releases/43 ": 1, "-X PATCH": 1,
			deleteCmd + "repos/rancher/suse-security-policies/releases/42": 1, deleteCmd: 1},
			before: map[string]string{"-X PATCH": deleteCmd}},
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
		{name: "draft read fails", rules: append(thrice(rule{prefix: ownRepo + "releases/42", err: "gh: Server Error (HTTP 502)"}), rerunRules()...),
			wantErr: draftCheck, forbid: noPatch, count: map[string]int{ownRepo + "releases/42": 3}},
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
		}, rerunRules()...), wantErr: "points at the commit", count: map[string]int{"-X PATCH": 1, ownRepo + "git/ref/tags/": 5},
			waits: []time.Duration{2 * time.Second, 8 * time.Second}},
		{name: "release is still a draft after the publication", rules: published(func(rel map[string]any, _ []map[string]any) { rel["draft"] = true }),
			wantErr: "draft is true instead of false", count: map[string]int{"-X PATCH": 1, ownRepo + "releases/42": 4},
			waits: []time.Duration{2 * time.Second, 8 * time.Second}},
		{name: "asset replaced at the publication", rules: published(func(_ map[string]any, assets []map[string]any) { assets[0]["digest"] = otherDigest }),
			wantErr: afterCheck, count: map[string]int{"-X PATCH": 1}, stdout: "A check after the publication failed",
			waits: []time.Duration{2 * time.Second, 8 * time.Second}},
		// Each try reads three times, because githubAPI retries a 502.
		{name: "read after the publication fails", rules: append([]rule{draftRead(nil), {prefix: ownRepo + "releases/42", err: "gh: Server Error (HTTP 502)"}}, rerunRules()...),
			wantErr: afterCheck, count: map[string]int{"-X PATCH": 1, ownRepo + "releases/42": 10},
			waits: []time.Duration{2 * time.Second, 8 * time.Second, 2 * time.Second, 2 * time.Second, 8 * time.Second, 8 * time.Second, 2 * time.Second, 8 * time.Second}},
		{name: "published release has no download location", rules: published(func(_ map[string]any, assets []map[string]any) {
			assets[0]["browser_download_url"] = "https://github.com/rancher/suse-security-policies/releases/download/untagged-1/" + suseWasmName
		}), wantErr: "the downloadLocation recorded in the SBOM", count: map[string]int{"-X PATCH": 1}, waits: []time.Duration{2 * time.Second, 8 * time.Second}},
		// The first draftRead serves the check of the draft, and the draftRead
		// of rerunRules serves the first read after the publication.
		{name: "release is a draft at the first read after the publication", rules: append([]rule{draftRead(nil)}, rerunRules()...),
			want: []string{ownList}, count: map[string]int{"-X PATCH": 1, ownRepo + "releases/42": 3}, waits: []time.Duration{2 * time.Second}},
		{name: "tag is missing at the first read after the publication", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", err: notFound, once: true}}, rerunRules()...),
			want: []string{ownList}, count: map[string]int{"-X PATCH": 1, ownRepo + "git/ref/tags/": 4}, waits: []time.Duration{2 * time.Second}},
		{name: "tag is missing at every read after the publication", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", err: notFound}}, rerunRules()...),
			wantErr: afterCheck, forbid: []string{ownList}, count: map[string]int{"-X PATCH": 1, ownRepo + "git/ref/tags/": 5},
			waits: []time.Duration{2 * time.Second, 8 * time.Second}, stdout: "A check after the publication failed"},
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
			wantErr: "cannot upload " + sourceArchiveName, forbid: []string{"-X PATCH", "?name=" + suseSBOMName + " "},
			count: map[string]int{"?name=" + sourceArchiveName + " ": 1}, waits: []time.Duration{}},
		{name: "publication fails", rules: append([]rule{{prefix: "gh api --hostname github.com -X PATCH ", err: "gh: Server Error (HTTP 502)"}}, rerunRules()...),
			wantErr: "HTTP 502", count: map[string]int{ownUpload + "42/assets?name=": 7, "-X PATCH": 1}, waits: []time.Duration{}},
		{name: "stale SBOM attestation", rules: append([]rule{{prefix: spdxCheck, fn: attested(staleSBOM)}}, rerunRules()...), wantErr: staleErr, forbid: noWrite},
		{name: "fresh run", rules: freshRules(), want: []string{"kwctl push", ownCreate},
			count: map[string]int{"cosign attest --yes --type spdxjson ": 1, "cosign sign --yes --new-bundle-format=false ": 1, "cosign sign --yes --use-signing-config=true ": 1, "-X PATCH": 1,
				"sbom-utility validate --input-file $WORK/" + draftSUSESBOMName: 1, "sbom-utility validate --input-file $WORK/" + suseSBOMName: 1}},
		{name: "SBOM attested but not signed", rules: append([]rule{
			{prefix: ownVerify, err: noSignatures, exit: 10, once: true},
			{prefix: signCheck, err: noSignatureAtt, exit: 1, once: true},
		}, rerunRules()...), forbid: []string{"cosign attest"},
			count: map[string]int{"cosign sign --yes --new-bundle-format=false ": 1, "cosign sign --yes --use-signing-config=true ": 1}},
		// The legacy signature exists, but none verifies with the identity of this repository.
		{name: "no matching legacy signature", rules: append([]rule{{prefix: ownVerify, err: "Error: no matching signatures: none of the expected identities matched", exit: 12, once: true}}, rerunRules()...),
			forbid: []string{"cosign attest", "cosign sign --yes --use-signing-config=true"}, count: map[string]int{"cosign sign --yes --new-bundle-format=false ": 1}},
		// A short network error must not hide the stale attestation of an earlier run.
		{name: "SBOM check fails with a network error", rules: append(append(thrice(rule{prefix: spdxCheck, err: timeout, exit: 1}),
			rule{prefix: spdxCheck, fn: attested(staleSBOM)}), rerunRules()...),
			wantErr: "cannot tell whether " + suseRef + " already has an SBOM attestation", forbid: noWrite, count: map[string]int{spdxCheck: 3}},
		// The retry passes the output of the last try to sameSBOM.
		{name: "SBOM check passes on the second try with a stale attestation", rules: append([]rule{{prefix: spdxCheck, err: timeout, exit: 1, once: true},
			{prefix: spdxCheck, fn: attested(staleSBOM)}}, rerunRules()...),
			wantErr: staleErr, forbid: noWrite, count: map[string]int{spdxCheck: 2}, waits: []time.Duration{2 * time.Second}},
		{name: "legacy check fails with a network error", rules: append(thrice(rule{prefix: ownVerify, err: badGate, exit: 1}), freshRules()...),
			wantErr: "cannot tell whether " + suseRef + " already has a legacy signature", forbid: noWrite, count: map[string]int{ownVerify: 3}},
		{name: "legacy check fails with a missing tag", rules: append(thrice(rule{prefix: ownVerify, err: "Error: image tag not found", exit: 11}), freshRules()...),
			wantErr: "cannot tell whether", forbid: noWrite, count: map[string]int{ownVerify: 3}},
		{name: "v3 check fails with a network error", rules: append(thrice(rule{prefix: signCheck, err: tooMany, exit: 1}), freshRules()...),
			wantErr: "cannot tell whether " + suseRef + " already has a v3 bundle signature", forbid: noWrite, count: map[string]int{signCheck: 3}},
		{name: "one stale and one current SBOM attestation", rules: append([]rule{{prefix: spdxCheck, fn: joined(attested(nil), attested(staleSBOM))}}, rerunRules()...),
			wantErr: staleErr, forbid: noWrite},
		{name: "stale SBOM attestation after the attestation", rules: append([]rule{
			{prefix: spdxCheck, err: noAttestations, exit: 1, once: true},
			{prefix: spdxCheck, fn: joined(attested(staleSBOM), attested(nil))},
		}, rerunRules()...), wantErr: staleErr, count: map[string]int{"cosign attest": 1}, forbid: []string{"cosign sign --", ownCreate, ownUpload, "-X PATCH"}},
		{name: "SBOM attestation that does not decode", rules: append([]rule{{prefix: spdxCheck, fn: joined(attested(nil), func(string) string { return "{not json\n" })}}, rerunRules()...),
			wantErr: staleErr, forbid: noWrite},
		{name: "blank lines in the SBOM attestation output", rules: append([]rule{{prefix: spdxCheck, fn: joined(attested(nil), func(string) string { return "\n \n" })}}, rerunRules()...),
			forbid: []string{"cosign sign --", "cosign attest"}, want: []string{"-X PATCH"}},
		{name: "SBOM check prints no attestation", rules: append([]rule{{prefix: spdxCheck, out: "\n"}}, rerunRules()...),
			wantErr: "cosign verify-attestation printed no SBOM attestation of " + suseRef, forbid: noWrite},
		// An earlier run wrote only the signatures.
		{name: "signed but SBOM not attested", rules: append([]rule{{prefix: spdxCheck, err: noSPDXAtt, exit: 1, once: true}}, rerunRules()...),
			forbid: []string{"cosign sign --"}, count: map[string]int{"cosign attest --yes --type spdxjson ": 1, "-X PATCH": 1}},
		{name: "read passes on the second try", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/releases/tags/", err: "gh: Server Error (HTTP 502)", once: true}}, rerunRules()...),
			want: []string{"-X PATCH"}, count: map[string]int{"gh api --hostname github.com repos/kubewarden/policies/releases/tags/": 2}, waits: []time.Duration{2 * time.Second}},
		{name: "rate limit on every try", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/releases/tags/", err: "gh: API rate limit exceeded (HTTP 429)"}}, rerunRules()...),
			wantErr: "HTTP 429", count: map[string]int{"gh api --hostname github.com repos/kubewarden/policies/releases/tags/": 3}, waits: []time.Duration{2 * time.Second, 8 * time.Second}},
		// rerunRules answer each check for our release and tag with a 404.
		{name: "no retry of a 404", rules: rerunRules(), want: []string{"-X PATCH"},
			count: map[string]int{ownRepo + "releases/tags/": 2, ownRepo + "git/ref/tags/": 3}, waits: []time.Duration{}},
		{name: "no retry of a missing destination tag", rules: freshRules(), want: []string{"kwctl push"}, count: map[string]int{destPull: 1}, waits: []time.Duration{}},
		{name: "destination pull passes on the second try", rules: append([]rule{{prefix: destPull, err: "Error: read tcp: connection reset by peer", once: true}}, rerunRules()...),
			want: []string{"-X PATCH"}, forbid: []string{"kwctl push"}, count: map[string]int{destPull: 2}, waits: []time.Duration{2 * time.Second}},
		{name: "signature check passes on the second try", rules: append([]rule{{prefix: ownVerify, err: timeout, exit: 1, once: true}}, rerunRules()...),
			want: []string{"-X PATCH"}, forbid: []string{"cosign sign --"}, count: map[string]int{ownVerify: 3}, waits: []time.Duration{2 * time.Second}},
		{name: "no retry when nothing is signed", rules: freshRules(), want: []string{"-X PATCH"},
			count: map[string]int{ownVerify: 2, spdxCheck: 2, signCheck: 2}, waits: []time.Duration{}},
		{name: "no retry of a failed creation", rules: append([]rule{{prefix: ownCreate, err: "gh: Server Error (HTTP 502)"}}, rerunRules()...),
			wantErr: "HTTP 502", forbid: noUpload, count: map[string]int{ownCreate: 1}, waits: []time.Duration{}},
		{name: "no retry of a failed push", rules: append([]rule{{prefix: "kwctl push", err: "Error: 502 Bad Gateway"}}, freshRules()...),
			wantErr: "502 Bad Gateway", forbid: noWrite, count: map[string]int{"kwctl push": 1}, waits: []time.Duration{}},
		{name: "no retry of a failed signature", rules: append([]rule{{prefix: "cosign sign --", err: timeout, exit: 1}}, freshRules()...),
			wantErr: "i/o timeout", forbid: []string{ownCreate}, count: map[string]int{"cosign sign --": 1}, waits: []time.Duration{}},
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
			if tt.noStdout != "" && strings.Contains(stdout, tt.noStdout) {
				t.Errorf("stdout contains %q:\n%s", tt.noStdout, stdout)
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
			if tt.waits != nil && !slices.Equal(f.waits, tt.waits) {
				t.Errorf("repackage waited %v instead of %v", f.waits, tt.waits)
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

// TestNothingSigned runs real processes, so that the test uses the errors of
// os/exec and not those of the fake.
func TestNothingSigned(t *testing.T) {
	oldLog := logOut
	logOut = io.Discard
	t.Cleanup(func() { logOut = oldLog })
	timedOut, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	tests := []struct {
		name string
		ctx  context.Context
		args []string
		want bool
	}{
		{name: "no matching signatures", args: []string{"sh", "-c", "exit 12"}, want: true},
		{name: "no signatures found", args: []string{"sh", "-c", "exit 10"}, want: true},
		{name: "tag not found", args: []string{"sh", "-c", "exit 11"}},
		{name: "no matching attestations", args: []string{"sh", "-c", "echo 'error during command execution: no matching attestations: ' >&2; exit 1"}, want: true},
		{name: "other error", args: []string{"sh", "-c", "echo 'error during command execution: dial tcp: i/o timeout' >&2; exit 1"}},
		{name: "killed by a signal", args: []string{"sh", "-c", "kill -9 $$"}},
		{name: "context timeout", ctx: timedOut, args: []string{"sleep", "5"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			_, err := realRun(ctx, tt.args[0], tt.args[1:]...)
			if err == nil {
				t.Fatal("the command did not fail")
			}
			if got := nothingSigned(err); got != tt.want {
				t.Errorf("nothingSigned(%q) is %v instead of %v", err, got, tt.want)
			}
		})
	}
}

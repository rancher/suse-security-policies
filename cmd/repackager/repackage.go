package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// The files in the work directory.
const (
	upstreamWasmName       = "upstream-policy.wasm"
	suseWasmName           = "suse-policy.wasm"
	suseWasmBundleName     = "suse-policy.wasm.bundle.sigstore"
	existingWasmName       = "existing-policy.wasm"
	upstreamMetadataName   = "upstream-metadata.yml"
	repackagedMetadataName = "repackaged-metadata.yml"
	upstreamSBOMName       = "upstream-policy-sbom.spdx.json"
	upstreamSBOMBundleName = "upstream-policy-sbom.spdx.jsonl.bundle.sigstore"
	suseSBOMName           = "policy-sbom.spdx.json"
	suseSBOMBundleName     = "policy-sbom.spdx.jsonl.bundle.sigstore"
	sourceArchiveName      = "upstream-source.tar.gz"
	releaseNotesName       = "release-notes.md"
)

// The assets of the upstream release.
const (
	upstreamSBOMAsset       = "policy-sbom.spdx.json"
	upstreamSBOMBundleAsset = "policy-sbom.spdx.jsonl.bundle.sigstore"
)

const (
	keyOCIURL  = "io.kubewarden.policy.ociUrl"
	keyAuthor  = "io.kubewarden.policy.author"
	keyVersion = "io.kubewarden.policy.version"
	// The --type filter makes sure that the SBOM attestation, which is also a
	// v3 bundle, does not count as a signature.
	signaturePredicateType = "https://sigstore.dev/cosign/sign/v1"
	ownOIDCIssuer          = "https://token.actions.githubusercontent.com"
)

var (
	// A short SHA or a branch name does not always name one fixed commit.
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// kwctl reports a tag that is not in the registry with these OCI codes.
	notFoundPattern = regexp.MustCompile(`(?i)(manifest|name)[ _]unknown`)
)

// repackageData holds the inputs of one run and the results of its steps.
type repackageData struct {
	cfg                                                                   *config
	repo, sha, workDir                                                    string
	dryRun                                                                bool
	name, version, tag, id, url                                           string
	upstream, upstreamRoot                                                any
	upstreamDigest, upstreamRef, immutableRef                             string
	destRef, sourceCommit, sourceSHA256, upstreamNamespace, suseNamespace string
	ownIdentity                                                           []string
}

func (d *repackageData) path(name string) string { return filepath.Join(d.workDir, name) }

// Sigstore compares the identity exactly, so the tag needs no escaping.
func (d *repackageData) upstreamIdentity() []string {
	return []string{
		"--certificate-identity", strings.ReplaceAll(d.cfg.Upstream.CertificateIdentityTemplate, "{tag}", d.tag),
		"--certificate-oidc-issuer", d.cfg.Upstream.CertificateOIDCIssuer,
	}
}

// signingIdentity reads GITHUB_WORKFLOW_REF, for example
// "owner/repo/.github/workflows/file.yaml@refs/heads/main". For a workflow
// that is not reusable, this value is equal to the job_workflow_ref that
// Fulcio writes into the certificate.
func signingIdentity(repo string) ([]string, error) {
	ref := os.Getenv("GITHUB_WORKFLOW_REF")
	if ref == "" {
		return nil, errors.New("GITHUB_WORKFLOW_REF is not set, so the signing identity is not known. Run the program in a GitHub Actions workflow, or use --dry-run")
	}
	if !strings.HasPrefix(ref, repo+"/.github/workflows/") || !strings.HasSuffix(ref, "@refs/heads/main") {
		return nil, fmt.Errorf("GITHUB_WORKFLOW_REF %q is not a workflow on the main branch of %s", ref, repo)
	}
	return []string{"--certificate-identity", "https://github.com/" + ref, "--certificate-oidc-issuer", ownOIDCIssuer}, nil
}

func verifyLegacySignature(ctx context.Context, ref string, identity []string) ([]byte, error) {
	return cosign(ctx, append([]string{"verify", ref, "--new-bundle-format=false", "--output", "json"}, identity...)...)
}

func verifyAttestation(ctx context.Context, ref, predicateType string, identity []string) ([]byte, error) {
	return cosign(ctx, append([]string{"verify-attestation", ref, "--type", predicateType}, identity...)...)
}

func signBlob(ctx context.Context, blob, bundle string) error {
	_, err := cosign(ctx, "sign-blob", "--yes", "--bundle", bundle, blob)
	return err
}

func verifyBlob(ctx context.Context, blob, bundle string, identity []string) error {
	_, err := cosign(ctx, append([]string{"verify-blob", blob, "--bundle", bundle}, identity...)...)
	return err
}

func repackage(ctx context.Context, d *repackageData) error {
	if err := checkPolicy(d.cfg, d.name, d.version); err != nil {
		return fmt.Errorf("repackage: %w", err)
	}
	if !shaPattern.MatchString(d.sha) {
		return fmt.Errorf("repackage: --sha %q is not a full commit SHA of 40 lowercase hex characters", d.sha)
	}
	var err error
	if !d.dryRun {
		if d.ownIdentity, err = signingIdentity(d.repo); err != nil {
			return fmt.Errorf("repackage: %w", err)
		}
	}
	d.tag = d.name + "/v" + d.version
	if d.workDir == "" {
		d.workDir, err = os.MkdirTemp("", "repackager-*")
		defer os.RemoveAll(d.workDir)
	} else {
		err = os.MkdirAll(d.workDir, 0o755)
	}
	if err == nil {
		err = repackageSteps(ctx, d)
	}
	if err != nil {
		return fmt.Errorf("repackage %s: %w", d.tag, err)
	}
	return nil
}

const (
	titleFindUpstream   = "Find the upstream release"
	titleVerifyUpstream = "Verify the upstream policy signature"
	titleAnnotate       = "Annotate the policy"
	titlePush           = "Push the repackaged policy"
	titleUpstreamSBOM   = "Download and verify the upstream SBOM"
	titleSUSESBOM       = "Generate the SUSE SBOM"
	titleDownloadSource = "Download the upstream source archive and render the release notes"
	titleSign           = "Sign and attest"
	titlePublish        = "Publish the release"
)

func repackageSteps(ctx context.Context, d *repackageData) error {
	if err := findUpstream(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleFindUpstream, err)
	}
	if err := verifyUpstream(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleVerifyUpstream, err)
	}
	if err := annotate(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleAnnotate, err)
	}
	if err := push(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titlePush, err)
	}
	if err := upstreamSBOM(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleUpstreamSBOM, err)
	}
	if err := suseSBOM(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleSUSESBOM, err)
	}
	if err := downloadSource(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleDownloadSource, err)
	}
	if d.dryRun {
		logf("::notice::Dry run: the program does not push, sign or publish anything")
		return nil
	}
	if err := sign(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleSign, err)
	}
	if err := publish(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titlePublish, err)
	}
	return nil
}

// findUpstream stops the run before anything is pushed or signed when our
// release or tag exists. It checks the upstream release like discover.
func findUpstream(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleFindUpstream)
	defer logf("::endgroup::")
	if exists, err := ghExists(ctx, "repos/"+d.repo+"/releases/tags/"+d.tag); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("the release %s is already published", d.tag)
	}
	if exists, err := ghExists(ctx, "repos/"+d.repo+"/git/ref/tags/"+d.tag); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("the tag %s exists without a published release. A person must check the tag", d.tag)
	}
	rel, err := decode(githubAPI(ctx, "repos/"+d.cfg.Upstream.Repository+"/releases/tags/"+d.tag))
	e := candidate(rel)
	if err == nil && e == nil {
		err = fmt.Errorf("%s has no release %s, or the release is a prerelease", d.cfg.Upstream.Repository, d.tag)
	}
	if err != nil {
		return err
	}
	d.url, d.upstream = e["upstream_release_url"], rel
	d.id, _, err = policyID(ctx, d.cfg, e)
	return err
}

// Later steps use the digest, so a tag that moves changes nothing.
func verifyUpstream(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleVerifyUpstream)
	defer logf("::endgroup::")
	repo := d.cfg.Upstream.Registry + "/" + d.id
	// cosign makes sure that each signed payload names the verified digest.
	out, err := decode(verifyLegacySignature(ctx, repo+":v"+d.version, d.upstreamIdentity()))
	if sigs := list(out); err == nil && len(sigs) > 0 {
		d.upstreamDigest = str(sigs[0], "critical", "image", "docker-manifest-digest")
	}
	if err != nil || !digestPattern.MatchString(d.upstreamDigest) {
		return cmp.Or(err, fmt.Errorf("the signature of %s:v%s names no sha256 digest", repo, d.version))
	}
	d.upstreamRef = repo + "@" + d.upstreamDigest
	_, err = verifyAttestation(ctx, d.upstreamRef, signaturePredicateType, d.upstreamIdentity())
	return err
}

// annotate keeps "io.kubewarden.policy.source", because this repository
// holds no source code. Without --metadata-path, kwctl keeps the rest.
func annotate(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleAnnotate)
	defer logf("::endgroup::")
	upstreamWasm, suseWasm := d.path(upstreamWasmName), d.path(suseWasmName)
	upstream, err := pullAndInspect(ctx, d.upstreamRef, upstreamWasm, d.path(upstreamMetadataName))
	if v, u := str(upstream, "annotations", keyVersion), str(upstream, "annotations", keyOCIURL); err == nil && (v != d.version || u != d.cfg.Upstream.Registry+"/"+d.id) {
		err = fmt.Errorf("the upstream module has the version %q and points at %q, but the release is %s of %s/%s", v, u, d.version, d.cfg.Upstream.Registry, d.id)
	}
	if err != nil {
		return err
	}
	want := map[string]string{
		keyOCIURL:                              d.cfg.Destination.Registry + "/" + d.id,
		keyAuthor:                              d.cfg.Metadata.Author,
		"io.kubewarden.policy.url":             d.cfg.Metadata.URL,
		"com.suse.policy.upstream.repository":  d.cfg.Upstream.Repository,
		"com.suse.policy.upstream.tag":         d.tag,
		"com.suse.policy.upstream.digest":      d.upstreamDigest,
		"com.suse.policy.upstream.release-url": d.url,
		"com.suse.policy.upstream.author":      str(upstream, "annotations", keyAuthor),
	}
	var annotations []string
	for _, k := range slices.Sorted(maps.Keys(want)) {
		// kwctl reads KEY=@PATH as "read the value from the file at PATH".
		if v := want[k]; v == "" || v == "null" || strings.HasPrefix(v, "@") || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("the value %q of %s is empty or \"null\", starts with '@', or has a newline", v, k)
		}
		annotations = append(annotations, "--annotation", k+"="+want[k])
	}
	repackaged, err := annotateAndInspect(ctx, annotations, upstreamWasm, suseWasm, d.path(repackagedMetadataName))
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got := str(repackaged, "annotations", k); err == nil && got != want[k] {
			err = fmt.Errorf("the repackaged policy has %s=%q instead of %q", k, got, want[k])
		}
	}
	// Without the new annotations, both documents must be equal. kwctl
	// annotate always writes its own version into "io.kubewarden.kwctl".
	for _, md := range []any{upstream, repackaged} {
		a, _ := get(md, "annotations").(map[string]any)
		maps.DeleteFunc(a, func(k string, _ any) bool { return want[k] != "" || k == "io.kubewarden.kwctl" })
	}
	if err == nil && !reflect.DeepEqual(upstream, repackaged) {
		err = fmt.Errorf("the repackaged policy changed metadata outside of the annotation allowlist. To compare %s and %s, run again with --work-dir", upstreamMetadataName, repackagedMetadataName)
	}
	return err
}

func pullAndInspect(ctx context.Context, ref, wasm, metadataFile string) (any, error) {
	if _, err := kwctl(ctx, "pull", "registry://"+ref, "-o", wasm); err != nil {
		return nil, err
	}
	return inspectMetadata(ctx, wasm, metadataFile)
}

func annotateAndInspect(ctx context.Context, annotations []string, in, out, metadataFile string) (any, error) {
	args := append(append([]string{"annotate"}, annotations...), "-o", out, in)
	if _, err := kwctl(ctx, args...); err != nil {
		return nil, err
	}
	return inspectMetadata(ctx, out, metadataFile)
}

func inspectMetadata(ctx context.Context, wasm, metadataFile string) (md any, err error) {
	data, err := kwctl(ctx, "inspect", "-o", "yaml", wasm)
	if err == nil {
		err = errors.Join(os.WriteFile(metadataFile, data, 0o644), yaml.Unmarshal(data, &md))
	}
	return md, err
}

// push never moves a tag, but reuses a tag with the same module bytes,
// because two pushes of one module can give two manifests. The second pull
// is by digest, so the tag cannot move before the signature.
func push(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titlePush)
	defer logf("::endgroup::")
	repo := d.cfg.Destination.Registry + "/" + d.id
	d.destRef = repo + ":v" + d.version
	suseWasm, existing := d.path(suseWasmName), d.path(existingWasmName)
	if _, err := kwctl(ctx, "pull", "registry://"+d.destRef, "-o", existing); err != nil {
		// The policy id comes from upstream, so it must not make the match.
		if !notFoundPattern.MatchString(strings.ReplaceAll(err.Error(), d.id, "")) {
			return fmt.Errorf("cannot tell whether %s already exists: %w", d.destRef, err)
		}
		if d.dryRun {
			logf("::notice::Dry run: the program does not push %s, so it does not generate or validate the SUSE SBOM", d.destRef)
			return nil
		}
		out, err := decode(kwctl(ctx, "push", "-o", "json", suseWasm, d.destRef))
		if d.immutableRef = str(out, "immutable_ref"); err == nil && !digestPattern.MatchString(strings.TrimPrefix(d.immutableRef, repo+"@")) {
			err = fmt.Errorf("kwctl push returned %q, which is not a digest reference of %s", d.immutableRef, repo)
		}
		return err
	}
	out, err := kwctl(ctx, "digest", "registry://"+d.destRef)
	ref := repo + "@" + strings.TrimSpace(string(out[bytes.LastIndexByte(out, '@')+1:]))
	if err == nil && !digestPattern.MatchString(strings.TrimPrefix(ref, repo+"@")) {
		err = fmt.Errorf("kwctl digest %s printed %q, which has no sha256 digest", d.destRef, strings.TrimSpace(string(out)))
	} else if err == nil {
		_, err = kwctl(ctx, "pull", "registry://"+ref, "-o", existing)
	}
	got, _ := fileSHA256(existing)
	if want, _ := fileSHA256(suseWasm); err == nil && got != want {
		err = fmt.Errorf("%s already exists and points at %s, which holds another module (sha256 %s, expected %s). The pipeline does not move a tag. A person must check the artifact and delete it by hand", d.destRef, ref, got, want)
	}
	d.immutableRef = ref
	return err
}

// upstreamSBOM verifies the copy that goes into the release.
func upstreamSBOM(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleUpstreamSBOM)
	defer logf("::endgroup::")
	sbom, bundle := d.path(upstreamSBOMName), d.path(upstreamSBOMBundleName)
	for _, asset := range [][2]string{{upstreamSBOMAsset, sbom}, {upstreamSBOMBundleAsset, bundle}} {
		if _, err := githubRelease(ctx, "download", d.tag, "--repo", "github.com/"+d.cfg.Upstream.Repository,
			"--pattern", asset[0], "--output", asset[1], "--clobber"); err != nil {
			return err
		}
	}
	if err := verifyBlob(ctx, sbom, bundle, d.upstreamIdentity()); err != nil {
		return err
	}
	doc, err := readJSON(sbom)
	d.upstreamNamespace = str(doc, "documentNamespace")
	if err != nil {
		return fmt.Errorf("parse the upstream SBOM: %w", err)
	} else if d.upstreamRoot, err = upstreamRoot(doc); err == nil && d.upstreamNamespace == "" {
		err = errors.New("the upstream SBOM has no documentNamespace, so the SUSE SBOM cannot refer to it")
	}
	return err
}

// downloadSource downloads by commit. Upstream does not sign the archive,
// so the commit in the upstream SBOM is the only link to check.
func downloadSource(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleDownloadSource)
	defer logf("::endgroup::")
	repo, archive := "repos/"+d.cfg.Upstream.Repository, d.path(sourceArchiveName)
	ref, err := decode(githubAPI(ctx, repo+"/git/ref/tags/"+d.tag))
	// An annotated tag points at a tag object. The limit stops a loop.
	for depth := 0; err == nil && depth < 10 && str(ref, "object", "type") == "tag"; depth++ {
		ref, err = decode(githubAPI(ctx, repo+"/git/tags/"+str(ref, "object", "sha")))
	}
	if err != nil {
		return err
	}
	d.sourceCommit = str(ref, "object", "sha")
	if typ, want := str(ref, "object", "type"), str(d.upstreamRoot, "versionInfo"); typ != "commit" || d.sourceCommit != want || !shaPattern.MatchString(want) {
		return fmt.Errorf("%s points at the %s %q, but the upstream SBOM records the commit %q", d.tag, typ, d.sourceCommit, want)
	}
	data, err := githubAPI(ctx, "--allow-escape-sequences", repo+"/tarball/"+d.sourceCommit)
	if err == nil {
		err = os.WriteFile(archive, data, 0o644)
	}
	d.sourceSHA256, _ = fileSHA256(archive)
	notes := []byte(renderReleaseNotes(d, cmp.Or(d.immutableRef, "<not pushed: dry run>"), str(d.upstream, "body")))
	return errors.Join(err, os.WriteFile(d.path(releaseNotesName), notes, 0o644))
}

// sign keeps a signature or an attestation of an earlier run that
// verifies. The legacy signature can carry only a Rekor v1 entry and no
// timestamp, so it does not use the signing config.
func sign(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleSign)
	defer logf("::endgroup::")
	ref, wasm, sbom := d.immutableRef, d.path(suseWasmName), d.path(suseSBOMName)
	wasmBundle, sbomBundle := d.path(suseWasmBundleName), d.path(suseSBOMBundleName)
	own := d.ownIdentity
	// An attestation of an earlier run can hold an older SBOM. This check
	// runs before any write, so that a stale attestation changes nothing.
	if out, err := verifyAttestation(ctx, ref, "spdxjson", own); err == nil {
		if err := sameSBOM(ref, out, sbom); err != nil {
			return err
		}
	} else if _, err := cosign(ctx, "attest", "--yes", "--type", "spdxjson", "--predicate", sbom, ref); err != nil {
		return err
	}
	if _, err := verifyLegacySignature(ctx, ref, own); err != nil {
		if _, err := cosign(ctx, "sign", "--yes", "--new-bundle-format=false", "--use-signing-config=false", ref); err != nil {
			return err
		}
	}
	if _, err := verifyAttestation(ctx, ref, signaturePredicateType, own); err != nil {
		if _, err := cosign(ctx, "sign", "--yes", "--use-signing-config=true", ref); err != nil {
			return err
		}
	}
	if err := signBlob(ctx, wasm, wasmBundle); err != nil {
		return err
	}
	if err := signBlob(ctx, sbom, sbomBundle); err != nil {
		return err
	}
	if _, err := verifyLegacySignature(ctx, ref, own); err != nil {
		return err
	}
	if _, err := verifyAttestation(ctx, ref, signaturePredicateType, own); err != nil {
		return err
	}
	out, err := verifyAttestation(ctx, ref, "spdxjson", own)
	if err == nil {
		err = sameSBOM(ref, out, sbom)
	}
	if err != nil {
		return err
	}
	if err := verifyBlob(ctx, wasm, wasmBundle, own); err != nil {
		return err
	}
	return verifyBlob(ctx, sbom, sbomBundle, own)
}

// sameSBOM returns nil if one attestation in the output of cosign
// verify-attestation holds the release SBOM. cosign prints one DSSE envelope
// per line, and its payload is the in-toto statement.
func sameSBOM(ref string, out []byte, sbom string) error {
	want, err := readJSON(sbom)
	for line := range bytes.Lines(out) {
		envelope, _ := decode(line, nil)
		payload, _ := base64.StdEncoding.DecodeString(str(envelope, "payload"))
		statement, _ := decode(payload, nil)
		got := get(statement, "predicate")
		// Some cosign versions store the document as a JSON string.
		if s, ok := got.(string); ok {
			got, _ = decode([]byte(s), nil)
		}
		if err == nil && reflect.DeepEqual(got, want) {
			return nil
		}
	}
	return cmp.Or(err, fmt.Errorf("the SBOM attestation of %s differs from the release SBOM. A person must delete the old attestation and run again", ref))
}

type releaseFile struct {
	size   int64
	sha256 string
}

// checkRelease treats a missing or null digest as a difference, so that a
// change of the GitHub API makes the check fail.
func checkRelease(rel any, d *repackageData, id int64, files map[string]releaseFile, wantDraft bool) error {
	var errs []error
	if got, ok := get(rel, "id").(float64); !ok || got != float64(id) {
		errs = append(errs, fmt.Errorf("the id is %v instead of %d", get(rel, "id"), id))
	}
	if get(rel, "draft") != wantDraft {
		errs = append(errs, fmt.Errorf("draft is %v instead of %v", get(rel, "draft"), wantDraft))
	}
	if str(rel, "tag_name") != d.tag {
		errs = append(errs, fmt.Errorf("tag_name is %q instead of %q", str(rel, "tag_name"), d.tag))
	}
	if str(rel, "target_commitish") != d.sha {
		errs = append(errs, fmt.Errorf("target_commitish is %q instead of %q", str(rel, "target_commitish"), d.sha))
	}
	seen := map[string]bool{}
	for _, a := range list(rel, "assets") {
		name := str(a, "name")
		f, ok := files[name]
		if !ok {
			errs = append(errs, fmt.Errorf("the asset %q is not expected", name))
			continue
		} else if seen[name] {
			errs = append(errs, fmt.Errorf("the release has the asset %q more than one time", name))
			continue
		}
		seen[name] = true
		if str(a, "state") != "uploaded" {
			errs = append(errs, fmt.Errorf("the asset %q has the state %v instead of \"uploaded\"", name, get(a, "state")))
		}
		if size, _ := get(a, "size").(float64); size != float64(f.size) {
			errs = append(errs, fmt.Errorf("the asset %q has the size %v instead of %d", name, get(a, "size"), f.size))
		}
		if str(a, "digest") != "sha256:"+f.sha256 {
			errs = append(errs, fmt.Errorf("the asset %q has the digest %v instead of sha256:%s", name, get(a, "digest"), f.sha256))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if !seen[name] {
			errs = append(errs, fmt.Errorf("the asset %q is missing", name))
		}
	}
	return errors.Join(errs...)
}

// publish uploads to a draft first, because only a draft can change.
// GitHub creates the tag at --sha on the publication.
func publish(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titlePublish)
	defer logf("::endgroup::")
	assets := []string{
		d.path(suseWasmName), d.path(suseWasmBundleName), d.path(sourceArchiveName), d.path(suseSBOMName),
		d.path(suseSBOMBundleName), d.path(upstreamSBOMName), d.path(upstreamSBOMBundleName),
	}
	files := map[string]releaseFile{}
	for _, a := range assets {
		info, err := os.Stat(a)
		if err != nil {
			return err
		}
		sum, err := fileSHA256(a)
		if err != nil {
			return err
		}
		files[filepath.Base(a)] = releaseFile{info.Size(), sum}
	}
	releases, err := releasesOf(ctx, d.repo)
	for _, r := range releases {
		if str(r, "tag_name") != d.tag || err != nil {
			continue
		} else if get(r, "draft") != true {
			return fmt.Errorf("the release %s is already published", d.tag)
		}
		_, err = githubAPI(ctx, "-X", "DELETE", fmt.Sprintf("repos/%s/releases/%.0f", d.repo, get(r, "id")))
	}
	var draft any
	if err == nil {
		draft, err = decode(githubAPI(ctx, "-X", "POST", "repos/"+d.repo+"/releases", "-f", "tag_name="+d.tag, "-f", "target_commitish="+d.sha,
			"-f", "name="+d.tag, "-F", "draft=true", "-f", "make_latest=false", "-F", "body=@"+d.path(releaseNotesName)))
	}
	if err != nil {
		return err
	}
	// The run does not look up the draft by its tag, because another draft can have the same tag.
	id, isNumber := get(draft, "id").(float64)
	uploadURL, _, _ := strings.Cut(str(draft, "upload_url"), "{")
	wantURL := fmt.Sprintf("https://uploads.github.com/repos/%s/releases/%d/assets", d.repo, int64(id))
	if !isNumber || id < 1 || id != math.Trunc(id) || id > 1<<53 || get(draft, "draft") != true || str(draft, "tag_name") != d.tag || uploadURL != wantURL {
		return fmt.Errorf("the response to the creation of the draft release %s is not as expected, so the run does not publish it: id %v, draft %v, tag_name %q, upload_url %q",
			d.tag, get(draft, "id"), get(draft, "draft"), str(draft, "tag_name"), str(draft, "upload_url"))
	}
	for _, a := range assets {
		if _, err := githubAPI(ctx, "-X", "POST", wantURL+"?name="+url.QueryEscape(filepath.Base(a)), "-H", "Content-Type: application/octet-stream", "--input", a); err != nil {
			return fmt.Errorf("cannot upload %s to the draft release %s: %w", filepath.Base(a), d.tag, err)
		}
	}
	releasePath, tagPath := fmt.Sprintf("repos/%s/releases/%d", d.repo, int64(id)), "repos/"+d.repo+"/git/ref/tags/"+d.tag
	published, err := ghExists(ctx, "repos/"+d.repo+"/releases/tags/"+d.tag)
	if err == nil && published {
		err = fmt.Errorf("the release %s is already published", d.tag)
	}
	// GitHub ignores target_commitish when the tag exists, so a tag that
	// somebody pushed during the run decides the commit of the release.
	var tagged bool
	if err == nil {
		tagged, err = ghExists(ctx, tagPath)
	}
	if err == nil && tagged {
		err = fmt.Errorf("the tag %s exists", d.tag)
	}
	var rel any
	if err == nil {
		rel, err = decode(githubAPI(ctx, releasePath))
	}
	if err == nil {
		err = checkRelease(rel, d, int64(id), files, true)
	}
	if err != nil {
		return fmt.Errorf("the check of the draft release %s failed, so the run does not publish it: %w", d.tag, err)
	}
	if _, err := githubAPI(ctx, "-X", "PATCH", releasePath, "-F", "draft=false", "-f", "make_latest=false"); err != nil {
		return err
	}
	// GitHub cannot check and publish a release in one call. Thus only these
	// reads show a change between the check above and the publication. After
	// the publication, the assets and the tag cannot change, so they are final.
	var ref any
	rel, err = decode(githubAPI(ctx, releasePath))
	if err == nil {
		ref, err = decode(githubAPI(ctx, tagPath))
	}
	if err == nil {
		// A draft has only a temporary download address.
		want := "https://github.com/" + d.repo + "/releases/download/" + d.tag + "/" + suseWasmName
		var noURL, wrongTag error
		if !slices.ContainsFunc(list(rel, "assets"), func(a any) bool { return str(a, "browser_download_url") == want }) {
			noURL = fmt.Errorf("the published release has no asset at %q, the downloadLocation recorded in the SBOM", want)
		}
		if typ, sha := str(ref, "object", "type"), str(ref, "object", "sha"); typ != "commit" || sha != d.sha {
			wrongTag = fmt.Errorf("the tag %s points at the %s %q instead of the commit %s", d.tag, typ, sha, d.sha)
		}
		err = errors.Join(checkRelease(rel, d, int64(id), files, false), noURL, wrongTag)
	}
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	if err := appendEnvFile("GITHUB_STEP_SUMMARY", cmdOut, releaseSummary(d, failure)); err != nil {
		logf("::warning::%s", escapeData(err.Error()))
	}
	if err != nil {
		return fmt.Errorf("the release %s is published and immutable, but a check after the publication failed. A person must check and fix the release by hand: %w", d.tag, err)
	}
	return nil
}

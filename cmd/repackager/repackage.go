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
	"time"

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
	draftSUSESBOMName      = "draft-policy-sbom.spdx.json"
	suseSBOMBundleName     = "policy-sbom.spdx.jsonl.bundle.sigstore"
	sourceArchiveName      = "upstream-source.tar.gz"
	releaseNotesName       = "release-notes.md"
	publishedDirName       = "published"
	registryWasmName       = "registry-policy.wasm"
)

var releaseAssets = []string{
	suseWasmName, suseWasmBundleName, sourceArchiveName, suseSBOMName, suseSBOMBundleName, upstreamSBOMName, upstreamSBOMBundleName,
}

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
	upstreamPublished                                                     time.Time
	upstreamDigest, upstreamRef, immutableRef                             string
	destRef, sourceCommit, sourceSHA256, upstreamNamespace, suseNamespace string
	ownIdentity                                                           []string
	published                                                             map[string]any
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
	return cosignVerify(ctx, append([]string{"verify", ref, "--new-bundle-format=false", "--output", "json"}, identity...)...)
}

func verifyAttestation(ctx context.Context, ref, predicateType string, identity []string) ([]byte, error) {
	return cosignVerify(ctx, append([]string{"verify-attestation", ref, "--type", predicateType}, identity...)...)
}

func signBlob(ctx context.Context, blob, bundle string) error {
	_, err := cosign(ctx, "sign-blob", "--yes", "--bundle", bundle, blob)
	return err
}

func verifyBlob(ctx context.Context, blob, bundle string, identity []string) error {
	_, err := cosignVerify(ctx, append([]string{"verify-blob", blob, "--bundle", bundle}, identity...)...)
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
	titleUpstreamSBOM   = "Download and verify the upstream SBOM"
	titleDownloadSource = "Download the upstream source archive"
	titleCheckSUSESBOM  = "Validate a draft of the SUSE SBOM"
	titlePush           = "Push the repackaged policy"
	titleSUSESBOM       = "Generate the SUSE SBOM"
	titleReleaseNotes   = "Render the release notes"
	titleSign           = "Sign and attest"
	titlePublish        = "Publish the release"
	titleVerifyRelease  = "Verify the published release"
)

func repackageSteps(ctx context.Context, d *repackageData) error {
	if err := findUpstream(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleFindUpstream, err)
	}
	if d.published != nil {
		if err := verifyPublished(ctx, d); err != nil {
			return fmt.Errorf("%s: %w", titleVerifyRelease, err)
		}
		return nil
	}
	if err := verifyUpstream(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleVerifyUpstream, err)
	}
	if err := annotate(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleAnnotate, err)
	}
	if err := upstreamSBOM(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleUpstreamSBOM, err)
	}
	if err := downloadSource(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleDownloadSource, err)
	}
	if err := checkSUSESBOM(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleCheckSUSESBOM, err)
	}
	// The checks above can fail for every run of an upstream release. The
	// push comes after them, so that it cannot leave an artifact in the
	// registry that no run can sign.
	if err := push(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titlePush, err)
	}
	if err := suseSBOM(ctx, d); err != nil {
		return fmt.Errorf("%s: %w", titleSUSESBOM, err)
	}
	if err := releaseNotes(d); err != nil {
		return fmt.Errorf("%s: %w", titleReleaseNotes, err)
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
// tag exists without a release. It keeps a published release in
// d.published, because the response of an earlier publication can get lost
// after GitHub published the release. It checks the upstream release like
// discover.
func findUpstream(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleFindUpstream)
	defer logf("::endgroup::")
	published, err := decode(githubAPI(ctx, "repos/"+d.repo+"/releases/tags/"+d.tag))
	if err == nil {
		var ok bool
		if d.published, ok = published.(map[string]any); !ok {
			return fmt.Errorf("the response for the release %s is not a JSON object", d.tag)
		}
	} else if !strings.Contains(err.Error(), "HTTP 404") {
		return err
	} else if exists, err := ghExists(ctx, "repos/"+d.repo+"/git/ref/tags/"+d.tag); err != nil {
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
	upstream, err := pullAndInspect(ctx, d.id, d.upstreamRef, upstreamWasm, d.path(upstreamMetadataName))
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

func pullAndInspect(ctx context.Context, id, ref, wasm, metadataFile string) (any, error) {
	if _, err := kwctlRead(ctx, id, "pull", "registry://"+ref, "-o", wasm); err != nil {
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
	if _, err := kwctlRead(ctx, d.id, "pull", "registry://"+d.destRef, "-o", existing); err != nil {
		if !tagMissing(err, d.id) {
			return fmt.Errorf("cannot tell whether %s already exists: %w", d.destRef, err)
		}
		if d.dryRun {
			logf("::notice::Dry run: the program does not push %s, so it does not generate the SUSE SBOM for the pushed digest", d.destRef)
			return nil
		}
		out, err := decode(kwctl(ctx, "push", "-o", "json", suseWasm, d.destRef))
		if d.immutableRef = str(out, "immutable_ref"); err == nil && !digestPattern.MatchString(strings.TrimPrefix(d.immutableRef, repo+"@")) {
			err = fmt.Errorf("kwctl push returned %q, which is not a digest reference of %s", d.immutableRef, repo)
		}
		return err
	}
	ref, err := digestRef(ctx, d.id, repo, d.destRef)
	if err == nil {
		_, err = kwctlRead(ctx, d.id, "pull", "registry://"+ref, "-o", existing)
	}
	got, _ := fileSHA256(existing)
	if want, _ := fileSHA256(suseWasm); err == nil && got != want {
		err = fmt.Errorf("%s already exists and points at %s, which holds another module (sha256 %s, expected %s). The pipeline does not move a tag. A person must check the artifact and delete it by hand", d.destRef, ref, got, want)
	}
	d.immutableRef = ref
	return err
}

func digestRef(ctx context.Context, id, repo, tagRef string) (string, error) {
	out, err := kwctlRead(ctx, id, "digest", "registry://"+tagRef)
	ref := repo + "@" + strings.TrimSpace(string(out[bytes.LastIndexByte(out, '@')+1:]))
	if err == nil && !digestPattern.MatchString(strings.TrimPrefix(ref, repo+"@")) {
		err = fmt.Errorf("kwctl digest %s printed %q, which has no sha256 digest", tagRef, strings.TrimSpace(string(out)))
	}
	return ref, err
}

// upstreamSBOM verifies the copy that goes into the release.
func upstreamSBOM(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleUpstreamSBOM)
	defer logf("::endgroup::")
	var err error
	if d.upstreamPublished, err = time.Parse(time.RFC3339, str(d.upstream, "published_at")); err != nil {
		return fmt.Errorf("the upstream release %s has no publication time: %w", d.tag, err)
	}
	sbom, bundle := d.path(upstreamSBOMName), d.path(upstreamSBOMBundleName)
	for _, asset := range [][2]string{{upstreamSBOMAsset, sbom}, {upstreamSBOMBundleAsset, bundle}} {
		if _, err := githubReleaseDownload(ctx, d.tag, "--repo", "github.com/"+d.cfg.Upstream.Repository,
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
	return err
}

func releaseNotes(d *repackageData) error {
	logf("::group::%s", titleReleaseNotes)
	defer logf("::endgroup::")
	notes := []byte(renderReleaseNotes(d, cmp.Or(d.immutableRef, "<not pushed: dry run>"), str(d.upstream, "body")))
	return os.WriteFile(d.path(releaseNotesName), notes, 0o644)
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
	// An attestation of an earlier run can hold an older SBOM. A check can
	// also fail for a reason that does not show whether a signature exists.
	// All checks run before the first write, so both cases stop the run
	// before it changes the registry.
	//
	// In cosign v3.1.3, a short registry error can still look like nothing
	// signed. verify-attestation falls back to the legacy format when the
	// referrers call fails (cmd/cosign/cli/verify/verify_attestation.go:142-146),
	// and GetBundles skips a bundle that it cannot download
	// (pkg/cosign/verify.go:1760-1765). Then the run attests again. If the old
	// SBOM differs, the check after signing stops the run before it
	// publishes, but the new attestation stays in the registry. A second
	// attestation of the same SBOM does no harm.
	sbomOut, sbomErr := verifyAttestation(ctx, ref, "spdxjson", own)
	_, legacyErr := verifyLegacySignature(ctx, ref, own)
	_, bundleErr := verifyAttestation(ctx, ref, signaturePredicateType, own)
	if sbomErr == nil {
		if err := sameSBOM(ref, sbomOut, sbom); err != nil {
			return err
		}
	}
	steps := []struct {
		what string
		err  error
		args []string
	}{
		{"an SBOM attestation", sbomErr, []string{"attest", "--yes", "--type", "spdxjson", "--predicate", sbom, ref}},
		{"a legacy signature", legacyErr, []string{"sign", "--yes", "--new-bundle-format=false", "--use-signing-config=false", ref}},
		{"a v3 bundle signature", bundleErr, []string{"sign", "--yes", "--use-signing-config=true", ref}},
	}
	for _, s := range steps {
		if s.err != nil && !nothingSigned(s.err) {
			return fmt.Errorf("cannot tell whether %s already has %s, so the run signs nothing: %w", ref, s.what, s.err)
		}
	}
	for _, s := range steps {
		if s.err == nil {
			continue
		}
		if _, err := cosign(ctx, s.args...); err != nil {
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

// nothingSigned reports whether a failed check means that the artifact has
// no signature or attestation of that kind that verifies with the identity.
// cosign verify exits with 10 (no signatures found) or 12 (no matching
// signatures) only for the legacy format. See
// cmd/cosign/errors/exit_codes.go of cosign v3.1.3. Exit code 11 (tag not
// found) does not count, because the reference is a digest that the run
// pushed. cosign verify-attestation always exits with 1, so only its error
// text tells the cases apart. The texts come from
// pkg/cosign/verify.go (ErrNoMatchingAttestations) and
// cmd/cosign/cli/verify/verify_attestation.go. cmd/cosign/main.go logs the
// error after "error during command execution: ".
func nothingSigned(err error) bool {
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) && (exit.ExitCode() == 10 || exit.ExitCode() == 12) {
		return true
	}
	return err != nil && (strings.Contains(err.Error(), "error during command execution: no matching attestations") ||
		strings.Contains(err.Error(), "error during command execution: none of the attestations matched the predicate type"))
}

// sameSBOM returns nil if the output of cosign verify-attestation holds at
// least one attestation, and every attestation holds the release SBOM.
// cosign prints only the attestations that verify with the identity and the
// type, one DSSE envelope per line. The payload of an envelope is the
// in-toto statement.
func sameSBOM(ref string, out []byte, sbom string) error {
	want, err := readJSON(sbom)
	if err != nil {
		return err
	}
	same, found := false, false
	for line := range bytes.Lines(out) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		found = true
		envelope, _ := decode(line, nil)
		payload, _ := base64.StdEncoding.DecodeString(str(envelope, "payload"))
		statement, _ := decode(payload, nil)
		got := get(statement, "predicate")
		// Some cosign versions store the document as a JSON string.
		if s, ok := got.(string); ok {
			got, _ = decode([]byte(s), nil)
		}
		if same = reflect.DeepEqual(got, want); !same {
			break
		}
	}
	if !found {
		return fmt.Errorf("cosign verify-attestation printed no SBOM attestation of %s", ref)
	}
	if same {
		return nil
	}
	return fmt.Errorf("one or more SBOM attestations of %s differ from the release SBOM. A person must delete the old attestations and run again", ref)
}

type releaseFile struct {
	size   int64
	sha256 string
}

func checkRelease(rel any, d *repackageData, id int64, files map[string]releaseFile, wantDraft bool) error {
	var errs []error
	if got, ok := get(rel, "id").(float64); !ok || got != float64(id) {
		errs = append(errs, fmt.Errorf("the id is %v instead of %d", get(rel, "id"), id))
	}
	if str(rel, "target_commitish") != d.sha {
		errs = append(errs, fmt.Errorf("target_commitish is %q instead of %q", str(rel, "target_commitish"), d.sha))
	}
	return errors.Join(append(errs, checkReleaseAssets(rel, d.tag, files, wantDraft)...)...)
}

// checkReleaseAssets treats a missing or null digest as a difference, so
// that a change of the GitHub API makes the check fail. A file with no
// sha256 is a file that the run could not download, so only the form of its
// digest counts.
func checkReleaseAssets(rel any, tag string, files map[string]releaseFile, wantDraft bool) []error {
	var errs []error
	if get(rel, "draft") != wantDraft {
		errs = append(errs, fmt.Errorf("draft is %v instead of %v", get(rel, "draft"), wantDraft))
	}
	if str(rel, "tag_name") != tag {
		errs = append(errs, fmt.Errorf("tag_name is %q instead of %q", str(rel, "tag_name"), tag))
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
		if f.sha256 == "" {
			if !digestPattern.MatchString(str(a, "digest")) {
				errs = append(errs, fmt.Errorf("the asset %q has the digest %v, which is not a sha256 digest", name, get(a, "digest")))
			}
			continue
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
	return errs
}

// publish uploads to a draft first, because only a draft can change.
// GitHub creates the tag at --sha on the publication.
func publish(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titlePublish)
	defer logf("::endgroup::")
	var assets []string
	for _, name := range releaseAssets {
		assets = append(assets, d.path(name))
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
	draft, err := decode(githubAPI(ctx, "-X", "POST", "repos/"+d.repo+"/releases", "-f", "tag_name="+d.tag, "-f", "target_commitish="+d.sha,
		"-f", "name="+d.tag, "-F", "draft=true", "-f", "make_latest=false", "-F", "body=@"+d.path(releaseNotesName)))
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
	checkPublished := func() error {
		rel, err := decode(githubAPI(ctx, releasePath))
		if err != nil {
			return err
		}
		ref, err := decode(githubAPI(ctx, tagPath))
		if err != nil {
			return err
		}
		// A draft has only a temporary download address.
		want := "https://github.com/" + d.repo + "/releases/download/" + d.tag + "/" + suseWasmName
		var noURL, wrongTag error
		if !slices.ContainsFunc(list(rel, "assets"), func(a any) bool { return str(a, "browser_download_url") == want }) {
			noURL = fmt.Errorf("the published release has no asset at %q, the downloadLocation recorded in the SBOM", want)
		}
		if typ, sha := str(ref, "object", "type"), str(ref, "object", "sha"); typ != "commit" || sha != d.sha {
			wrongTag = fmt.Errorf("the tag %s points at the %s %q instead of the commit %s", d.tag, typ, sha, d.sha)
		}
		return errors.Join(checkRelease(rel, d, int64(id), files, false), noURL, wrongTag)
	}
	// Right after the publication, GitHub can still show the release as a
	// draft or the tag as missing for a short time, so a failed check gets
	// more tries. The check of the draft gets no retry. If it fails, the run
	// stops before the publication, and a later run can try again.
	err = checkPublished()
	for _, wait := range retryWaits {
		if err == nil || ctx.Err() != nil {
			break
		}
		logf("::warning::%s", escapeData(fmt.Sprintf("the check of the published release %s failed: %v. The run tries again in %s.", d.tag, err, wait)))
		if sleep(ctx, wait) != nil {
			break
		}
		err = checkPublished()
	}
	failure, cleanupFailure := "", ""
	if err != nil {
		failure = err.Error()
	} else if err := deleteOldDrafts(ctx, d, int64(id)); err != nil {
		// The run does not fail, because the release is correct and a rerun
		// for a published release does not change it.
		cleanupFailure = err.Error()
		logf("::warning::%s", escapeData(fmt.Sprintf("the release %s is published, but the run cannot delete one or more old drafts for the tag: %v", d.tag, err)))
	}
	if err := appendEnvFile("GITHUB_STEP_SUMMARY", cmdOut, releaseSummary(d, failure, cleanupFailure)); err != nil {
		logf("::warning::%s", escapeData(err.Error()))
	}
	if err != nil {
		return fmt.Errorf("the release %s is published and immutable, but a check after the publication failed. A person must check and fix the release by hand: %w", d.tag, err)
	}
	return nil
}

// deleteOldDrafts deletes the drafts with the tag of d, except the release keep.
//
// deleteOldDrafts runs only after the publication. GitHub refuses to publish
// a second release with a tag that has a published release, so after the
// publication nobody can publish an old draft with the tag. The second read
// finds a draft that a person published or moved to another tag. A small time
// window stays between the read and the delete, because GitHub has no
// conditional delete.
func deleteOldDrafts(ctx context.Context, d *repackageData, keep int64) error {
	releases, err := releasesOf(ctx, d.repo)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range releases {
		id, isNumber := get(r, "id").(float64)
		if str(r, "tag_name") != d.tag || get(r, "draft") != true || !isNumber || id < 1 || id != math.Trunc(id) || id > 1<<53 || int64(id) == keep {
			continue
		}
		path := fmt.Sprintf("repos/%s/releases/%d", d.repo, int64(id))
		rel, err := decode(githubAPI(ctx, path))
		if err == nil && (get(rel, "draft") != true || str(rel, "tag_name") != d.tag) {
			logf("keep the release %d: it is no longer a draft with the tag %s", int64(id), d.tag)
			continue
		}
		if err == nil {
			_, err = githubAPI(ctx, "-X", "DELETE", path)
		}
		if err != nil && strings.Contains(err.Error(), "HTTP 404") {
			logf("the release %d is already gone", int64(id))
		} else if err != nil {
			errs = append(errs, fmt.Errorf("release %d: %w", int64(id), err))
		}
	}
	return errors.Join(errs...)
}

// verifyPublished only reads, so it runs the same way in a dry run. A new
// run cannot make the source archive and the sign-blob bundles again with
// the same bytes, so the checks use the digests and the signatures of the
// release. The source archive has no signature, so only its digest is
// checked.
func verifyPublished(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleVerifyRelease)
	defer logf("::endgroup::")
	own := d.ownIdentity
	if own == nil {
		var err error
		if own, err = signingIdentity(d.repo); err != nil {
			return fmt.Errorf("the run needs GITHUB_WORKFLOW_REF to verify the published release %s: %w", d.tag, err)
		}
	}
	err := errors.Join(publishedErrors(ctx, d, own)...)
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	if err := appendEnvFile("GITHUB_STEP_SUMMARY", cmdOut, publishedSummary(d, failure)); err != nil {
		logf("::warning::%s", escapeData(err.Error()))
	}
	if err != nil {
		return fmt.Errorf("the release %s is published and immutable, but a check of the published release failed. A person must check the release by hand: %w", d.tag, err)
	}
	return nil
}

func publishedErrors(ctx context.Context, d *repackageData, own []string) []error {
	dir := d.path(publishedDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []error{err}
	}
	path := func(name string) string { return filepath.Join(dir, name) }
	var errs []error
	ref, err := decode(githubAPI(ctx, "repos/"+d.repo+"/git/ref/tags/"+d.tag))
	// A release of an earlier run has the commit of that run, not d.sha.
	commit := str(d.published, "target_commitish")
	if typ, sha := str(ref, "object", "type"), str(ref, "object", "sha"); err == nil && (typ != "commit" || sha != commit || !shaPattern.MatchString(sha)) {
		err = fmt.Errorf("the tag %s points at the %s %q instead of the commit %q of the release", d.tag, typ, sha, commit)
	}
	errs = append(errs, err)
	files := map[string]releaseFile{}
	for _, name := range releaseAssets {
		files[name] = releaseFile{}
		if _, err := githubReleaseDownload(ctx, d.tag, "--repo", "github.com/"+d.repo, "--pattern", name, "--output", path(name), "--clobber"); err != nil {
			errs = append(errs, fmt.Errorf("cannot download the asset %q: %w", name, err))
			continue
		}
		info, err := os.Stat(path(name))
		sum, err2 := fileSHA256(path(name))
		if err = errors.Join(err, err2); err != nil {
			errs = append(errs, err)
			continue
		}
		files[name] = releaseFile{info.Size(), sum}
	}
	errs = append(errs, checkReleaseAssets(d.published, d.tag, files, false)...)
	have := func(names ...string) bool {
		return !slices.ContainsFunc(names, func(n string) bool { return files[n].sha256 == "" })
	}
	for _, b := range []struct {
		blob, bundle string
		identity     []string
	}{{suseWasmName, suseWasmBundleName, own}, {suseSBOMName, suseSBOMBundleName, own}, {upstreamSBOMName, upstreamSBOMBundleName, d.upstreamIdentity()}} {
		if !have(b.blob, b.bundle) {
			continue
		}
		if err := verifyBlob(ctx, path(b.blob), path(b.bundle), b.identity); err != nil {
			errs = append(errs, fmt.Errorf("the signature of the asset %q does not verify: %w", b.blob, err))
		}
	}
	repo := d.cfg.Destination.Registry + "/" + d.id
	d.destRef = repo + ":v" + d.version
	immutableRef, err := digestRef(ctx, d.id, repo, d.destRef)
	if err != nil {
		return append(errs, err)
	}
	d.immutableRef = immutableRef
	wasmSum := files[suseWasmName].sha256
	if _, err := kwctlRead(ctx, d.id, "pull", "registry://"+immutableRef, "-o", path(registryWasmName)); err != nil {
		errs = append(errs, err)
	} else if got, _ := fileSHA256(path(registryWasmName)); have(suseWasmName) && got != wasmSum {
		errs = append(errs, fmt.Errorf("%s holds a module with sha256 %s, but the asset %q of the release has sha256 %s", immutableRef, got, suseWasmName, wasmSum))
	}
	if _, err := verifyLegacySignature(ctx, immutableRef, own); err != nil {
		errs = append(errs, err)
	}
	if _, err := verifyAttestation(ctx, immutableRef, signaturePredicateType, own); err != nil {
		errs = append(errs, err)
	}
	out, err := verifyAttestation(ctx, immutableRef, "spdxjson", own)
	if err == nil && have(suseSBOMName) {
		err = sameSBOM(immutableRef, out, path(suseSBOMName))
	}
	errs = append(errs, err)
	if !have(suseSBOMName, suseWasmName) {
		return errs
	}
	doc, err := readJSON(path(suseSBOMName))
	if err != nil {
		return append(errs, fmt.Errorf("parse the asset %q: %w", suseSBOMName, err))
	}
	if upstreamSum := files[upstreamSBOMName].sha256; have(upstreamSBOMName) && !slices.ContainsFunc(list(doc, "externalDocumentRefs"), func(r any) bool {
		return str(r, "checksum", "algorithm") == "SHA256" && str(r, "checksum", "checksumValue") == upstreamSum
	}) {
		errs = append(errs, fmt.Errorf("the asset %q does not record the SHA256 checksum %s of the asset %q", suseSBOMName, upstreamSum, upstreamSBOMName))
	}
	i := slices.IndexFunc(list(doc, "packages"), func(p any) bool { return str(p, "SPDXID") == "SPDXRef-Package-"+d.id })
	if i < 0 {
		return append(errs, fmt.Errorf("the asset %q has no package SPDXRef-Package-%s", suseSBOMName, d.id))
	}
	pkg := list(doc, "packages")[i]
	if !slices.ContainsFunc(list(pkg, "checksums"), func(c any) bool { return str(c, "algorithm") == "SHA256" && str(c, "checksumValue") == wasmSum }) {
		errs = append(errs, fmt.Errorf("the asset %q does not record the SHA256 checksum %s of the asset %q", suseSBOMName, wasmSum, suseWasmName))
	}
	_, digest, _ := strings.Cut(immutableRef, "@")
	if !slices.ContainsFunc(list(pkg, "externalRefs"), func(r any) bool {
		return str(r, "referenceType") == "purl" && strings.Contains(str(r, "referenceLocator"), "@"+strings.Replace(digest, ":", "%3A", 1))
	}) {
		errs = append(errs, fmt.Errorf("the purl in the asset %q does not name the digest %s", suseSBOMName, digest))
	}
	return errs
}

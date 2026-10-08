# SUSE Security Policies

This repository republishes the Kubewarden policies maintained in
[kubewarden/policies](https://github.com/kubewarden/policies) under SUSE
identity, into a private OCI registry.

It contains **no policy source code**. Nothing is compiled here. The CI takes
the WebAssembly module that the upstream project already built and signed,
checks that signature, rewrites the provenance metadata, signs the result with
this repository's own identity and publishes it.

Policy bugs and feature requests belong upstream. Only packaging, signing and
distribution issues belong here.

## What the pipeline guarantees

- The published module is the upstream one. It is pulled by digest from the
  verified upstream artifact and only re-annotated, never rebuilt.
- The upstream artifact is verified against a Sigstore identity **pinned to the
  exact release tag** before it is used. A signature from the upstream release
  workflow for a different policy or version is rejected.
- The verified tag is immediately resolved to a digest, and the digest is used
  for every later step, so a tag moved mid-run cannot swap the artifact.
- Metadata changes are restricted to an allowlist. Any change to `rules`,
  `mutating`, `contextAware`, `executionMode` or the policy version fails the
  build (`hack/check-metadata-diff.sh`).
- The upstream SBOM is verified, then republished **byte-identical**, so it
  keeps verifying against the upstream Sigstore identity on the file we ship.
  A missing or unverifiable SBOM fails the release.
- A second, SUSE SBOM describes the artifact we publish and is bound to it by
  sha256 and by OCI digest. It is signed, attested to the pushed manifest, and
  every field in it is checked against the real files before the release is
  created (`hack/verify-sbom.sh`).

## How it works

```
                 kubewarden/policies
                   releases + GHCR
                          |
   (1) discover           v
   hourly cron ---> sync-upstream-releases.yaml
                          |  matrix of policies missing a release here
                          v
   (2) repackage ---> repackage-policy.yaml
                          |
       verify upstream signature (pinned to the tag)
       pull by digest
       rewrite provenance metadata, re-annotate
       check nothing else moved
       push and sign in the destination registry
       verify our own signature
       republish the upstream SBOM, generate + sign + attest the SUSE one
       check the SUSE SBOM against the artifacts
                          |
                          v
          GitHub release in this repository
          + signed artifact and SBOM attestation in the private registry
```

### 1. Discovery — `.github/workflows/sync-upstream-releases.yaml`

Runs hourly. Lists upstream releases, keeps the highest version per policy,
drops prereleases and the policies upstream itself does not publish, then skips
anything that already has a release here.

The **existence of the GitHub release in this repository is the source of
truth** for "already published". The release is created as the very last step
of the repackaging job, so a run that fails halfway leaves no release behind
and the next cron retries it.

Only the latest version of each policy is published. History is not backfilled.

### 2. Repackaging — `.github/workflows/repackage-policy.yaml`

Handles exactly one policy version. See the step comments in the workflow for
the details of each stage.

## SBOMs

Every release carries two SPDX documents, because there are two separate claims
to make and one document cannot make both honestly.

| Asset | Describes | Signed by |
|---|---|---|
| `upstream-policy-sbom.spdx.json` | what upstream scanned | upstream, original bundle |
| `policy-sbom.spdx.json` | the artifact SUSE ships | this repository |

**The upstream document is never modified.** It is downloaded, verified against
the upstream identity, renamed and attached as is. The signature check runs on
the renamed copy, which is both an authenticity check and a proof that the file
reaching the release is byte-identical to the one upstream signed.

**The SUSE document is generated from scratch** by `hack/generate-sbom.sh`. It
is a distribution record, not a scan: one package, describing `suse-policy.wasm`
and nothing else. It records

- the sha256 of the module and the `pkg:oci` purl of the pushed manifest, so the
  document is bound to the bytes we publish,
- `supplier: SUSE` and `originator: Kubewarden`, which is how SPDX distinguishes
  the party that distributes an artifact from the party that created it,
- the upstream repository, release tag, OCI digest and source commit in
  `sourceInfo`,
- the licence fields **copied** from the upstream root package, never asserted,
- an `externalDocumentRefs` entry naming the upstream document by namespace and
  binding it by sha256, plus a `GENERATED_FROM` relationship pointing into it.

Those last two are what replace the old practice of rewriting upstream's
document: the link between the two is now a reference the SPDX spec defines and
tools can follow, instead of a sentence in a comment field.

The SUSE document is signed with `cosign sign-blob` and attested to the pushed
manifest with `cosign attest --type spdxjson`. The attestation matters because
Kubewarden pulls policies from the registry, not from GitHub releases; without
it the SBOM would be invisible to everything that consumes the module.

Before the release is created, `hack/verify-sbom.sh` checks the generated
document against the real files: SPDX 2.3 schema validity, the upstream
reference against the attached upstream file, the package checksum against the
attached module, the purl against the push output, and that the provenance link
resolves to a package the upstream document actually contains. The signature and
attestation are verified in the same stage. Nothing in the document reaches a
consumer unchecked.

### Verifying a release

```sh
# The upstream claim, against the upstream identity
cosign verify-blob upstream-policy-sbom.spdx.json \
  --bundle upstream-policy-sbom.spdx.jsonl.bundle.sigstore \
  --certificate-identity-regexp '^https://github\.com/kubewarden/policies/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The SUSE claim, against this repository
cosign verify-blob policy-sbom.spdx.json \
  --bundle policy-sbom.spdx.jsonl.bundle.sigstore \
  --certificate-identity-regexp '^https://github\.com/rancher/suse-security-policies/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The same document, from the registry
cosign verify-attestation ghcr.io/rancher/suse-security-policies/<policy-id>:v<version> \
  --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/rancher/suse-security-policies/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Running it by hand

```sh
# Repackage everything that is missing
gh workflow run sync-upstream-releases.yaml

# Repackage a single policy at its latest version
gh workflow run sync-upstream-releases.yaml -f policy-name=pod-privileged-policy

# Repackage a specific, possibly older, version
gh workflow run sync-upstream-releases.yaml \
  -f policy-name=pod-privileged-policy \
  -f policy-version=1.0.13

# Republish something that already has a release
gh workflow run sync-upstream-releases.yaml \
  -f policy-name=pod-privileged-policy \
  -f force=true
```

`force` deletes the existing release and its tag before recreating it.

## Configuration

Everything environment specific lives in [`config.yaml`](config.yaml):
the upstream repository and registry, the expected signer identity, the
destination registry, the SUSE metadata and SBOM values, the pinned tools and
the excluded policy list.

Moving to a different registry later means editing `config.yaml` and the
registry login step, nothing else.

### Updating the pinned tools

`kwctl`, `wasm-tools` and `sbom-utility` are pinned by version **and sha256** in
`config.yaml`. Renovate does not manage them, because bumping a version without
the matching checksum would produce pull requests that always fail. To upgrade,
update both fields together. For `kwctl` the source is the
[kubewarden-controller releases](https://github.com/kubewarden/kubewarden-controller/releases).
Neither `wasm-tools` nor `sbom-utility` publishes a sha256 file, so those values
are computed from the released archive.

Note that `kwctl annotate` stamps the module with the version of the tool that
ran, so changing the pin changes the
`io.kubewarden.policy.kwctl-version` annotation of everything published
afterwards. That annotation is on the allowlist, so this is expected.

### Keeping the excluded list in sync

`excluded_policies` mirrors `EXCLUDED_FROM_PUBLISHING` in the upstream release
workflow. Upstream builds those policies but does not publish them, because
they are demos and test fixtures. If upstream changes that list, update
`config.yaml` to match.

## Scripts

| Script | Purpose |
|---|---|
| `hack/discover-releases.sh` | Decide which upstream releases still need repackaging |
| `hack/adapt-metadata.sh` | Rewrite the provenance annotations for SUSE |
| `hack/check-metadata-diff.sh` | Fail if anything outside the allowlist changed |
| `hack/check-repackaged-metadata.sh` | Fail if the result does not carry the new metadata |
| `hack/generate-sbom.sh` | Build the SUSE SPDX document for the repackaged artifact |
| `hack/verify-sbom.sh` | Fail if that document does not match the files being released |
| `hack/render-changelog.sh` | Build the release notes from the upstream changelog |

They read `config.yaml` and take their inputs from the environment, so they can
be run locally.

## Known kwctl behaviour

`kwctl annotate` adds a metadata section to the module instead of replacing the
section that is already there, and a reader takes the first section it finds. A
module that is annotated a second time therefore keeps reporting the old
metadata.

The workflow removes the old section with `wasm-tools` before it annotates the
module, and `hack/check-repackaged-metadata.sh` then confirms that the result
carries the new values.

## Known limitations

- **Neither SBOM contains a dependency inventory.** The upstream syft scan
  produces a single directory-root package with no dependencies and no licence
  data, so there is nothing for us to preserve and nothing for a consumer to
  scan. See
  [`docs/upstream-sbom-no-dependency-inventory.md`](docs/upstream-sbom-no-dependency-inventory.md).
- Releases of the same policy all land on the same commit of the default
  branch, because this repository holds no policy source. The tags are
  therefore meaningful only as version markers.

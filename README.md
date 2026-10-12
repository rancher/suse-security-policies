# SUSE Security Policies

This repository republishes the Kubewarden policies of
[kubewarden/policies](https://github.com/kubewarden/policies) under the SUSE
identity, into a private OCI registry.

The repository contains no policy source code, and nothing is compiled here.
The upstream project builds and signs a WebAssembly module for each policy.
The CI of this repository takes that module and checks its signature. Then it
changes the provenance metadata, signs the result with the identity of this
repository and publishes it. Provenance is the record of where an artifact
comes from.

Report policy bugs and feature requests upstream. Report only packaging,
signing and distribution problems here.

## What the pipeline guarantees

- The published module is the upstream module. The workflow pulls it by
  digest from the upstream artifact that it checked. A digest is the sha256
  hash that identifies one artifact. The workflow does not compile the module
  again. `kwctl annotate` reads the module, replaces the metadata section, and
  writes the module out again. The workflow checks that the metadata outside
  the allowlist did not change. It does not compare the other bytes of the
  module with the upstream module.
- Before the workflow uses the upstream artifact, it checks the signature
  against a Sigstore identity. That identity names the exact release tag, so
  a signature from the upstream release workflow for a different policy or
  version fails. The workflow compares the identity as an exact string, not as
  a regular expression. Thus no character of the tag can widen the match.
- The workflow converts the tag to a digest before the signature check. Every
  later step uses that digest. If somebody moves the tag during the run, the
  artifact does not change.
- The metadata inside the module must name the policy id and the version of
  the release (`hack/check-upstream-metadata.sh`). Discovery reads those
  values from git. This check makes sure that git and the module agree.
- Only the annotations on an allowlist can change. A change to `rules`,
  `mutating`, `contextAware`, `executionMode` or the policy version stops the
  build (`hack/check-metadata-diff.sh`).
- The `io.kubewarden.policy.source` annotation keeps the upstream value. It
  tells where the source code is, and this repository contains no source code.
  A change to this annotation stops the build.
- The `io.kubewarden.policy.author` annotation names SUSE, the publisher. The
  `com.suse.policy.upstream.author` annotation keeps the upstream author.
- The workflow signs the repackaged module two times with the identity of this
  repository. One signature is on the OCI artifact in the registry. The other
  signature, from `cosign sign-blob`, is on the `suse-policy.wasm` file on the
  release page. The workflow checks both signatures before it creates the
  release.
- Only the `main` branch publishes. A run from another branch stops before
  discovery. The workflow checks every signature that it makes against the
  exact identity
  `https://github.com/rancher/suse-security-policies/.github/workflows/repackage-policy.yaml@refs/heads/main`.
  A signature from another branch fails that check.
- The release contains `upstream-source.tar.gz`. This is the GitHub archive of
  the upstream repository at the commit that the module was built from. The
  workflow downloads the archive by commit. The run stops if the upstream tag
  and the upstream SBOM name a different commit. Upstream does not sign this
  archive. GitHub does not promise that an archive stays byte-identical over
  time. Thus the sha256 in the release notes describes only the attached file.
- An SBOM (software bill of materials) is a list of what an artifact contains.
  The workflow checks the signature of the upstream SBOM. Then it republishes
  the SBOM byte-identical, so the file still passes the check against the
  upstream Sigstore identity. If the SBOM is missing or its signature fails,
  the release stops.
- A second SBOM, the SUSE SBOM, describes the artifact that SUSE publishes. It
  records the sha256 and the OCI digest of that artifact. The workflow signs
  the SUSE SBOM and attests it to the pushed manifest. An attestation is a
  signed statement that the registry stores next to the artifact. Before the
  release, the workflow compares every field of the SUSE SBOM with the real
  files (`hack/verify-sbom.sh`).
- The workflow signs nothing until every check that can run before the
  release passes. If a step fails, the run deletes the release that it
  created. It also deletes the artifact that it pushed, with the signatures
  and the attestation. It never deletes an artifact that an earlier run
  released.
- If a forced republish fails, the tag continues to point at the new digest,
  which did not pass every check. The run reports the previous digest, so you
  can move the tag back.

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
       check the module metadata names the release
       patch the provenance annotations in place
       check nothing else moved
       push to the destination registry, unsigned
       republish the upstream SBOM, generate the SUSE one
       check the SUSE SBOM against the artifacts
       attach the upstream source archive of the release commit
       sign the artifact, the module file and the SUSE SBOM
       attest the SUSE SBOM, verify our own signatures
       create the release
       on failure: delete the release and the pushed artifact
                          |
                          v
          GitHub release in this repository
          + signed artifact and SBOM attestation in the private registry
```

### 1. Discovery: `.github/workflows/sync-upstream-releases.yaml`

The discovery workflow runs one time each hour. It lists the upstream
releases and keeps the highest version of each policy. It removes
prereleases and the policies that upstream does not publish. Then it removes
each release that already has a release in this repository.

A GitHub release in this repository is the only record that a version is
published. The repackaging job creates the release as its last step. If a run
fails after it created the release, it deletes the release. Thus the next
hourly run tries again.

The workflow publishes only the latest version of each policy. It does not
publish older versions.

### 2. Repackaging: `.github/workflows/repackage-policy.yaml`

The repackaging workflow handles one policy version. The comments on the steps
of the workflow explain each stage.

## SBOMs

Each release contains two SPDX documents. The two documents make two
different claims, and one document cannot make both claims.

| Asset | Describes | Signed by |
|---|---|---|
| `upstream-policy-sbom.spdx.json` | what upstream scanned | upstream, original bundle |
| `policy-sbom.spdx.json` | the artifact SUSE ships | this repository |

The workflow never changes the upstream document. It downloads the document,
checks the signature against the upstream identity, gives the file a new name
and attaches it. The signature check runs on the renamed copy. Thus the check
proves two facts. The document comes from upstream, and the file in the
release is byte-identical to the file that upstream signed.

The script `hack/generate-sbom.sh` writes the SUSE document. The document is a
distribution record, not a scan. It contains one package, which describes
`suse-policy.wasm` and nothing else. The document records these items:

- The sha256 of the module and the `pkg:oci` purl of the pushed manifest. A
  purl is a package URL. These two values tie the document to the bytes that
  SUSE publishes.
- `supplier: SUSE` and `originator: Kubewarden`. SPDX uses these two fields to
  separate the party that distributes an artifact from the party that made it.
- The upstream repository, the release tag, the OCI digest and the source
  commit, in `sourceInfo`.
- The license fields, copied from the root package of the upstream document.
  SUSE does not state its own license conclusion.
- An `externalDocumentRefs` entry. It names the upstream document by its
  namespace and ties it to the document by its sha256. A `GENERATED_FROM`
  relationship points into the upstream document.

The last two items replace the old method, which changed the upstream
document. The SPDX specification defines this type of reference, and tools can
follow it. The old method used a sentence in a comment field.

The workflow signs the SUSE document with `cosign sign-blob`. It also attests
the document to the pushed manifest with `cosign attest --type spdxjson`.
Kubewarden pulls policies from the registry, not from GitHub releases. Without
the attestation, tools that use the module cannot find the SBOM.

Before the workflow creates the release, `hack/verify-sbom.sh` compares the
document with the real files. The script makes sure that:

1. The document is valid SPDX 2.3.
2. The upstream reference matches the attached upstream file.
3. The package checksum matches the attached module.
4. The purl matches the output of the push.
5. The provenance link points at a package that the upstream document
   contains.

The same stage checks the signature and the attestation. No field of the
document reaches a user without a check.

### Verifying a release

```sh
# Every signature this repository makes carries this identity. Do not accept
# a looser pattern: a signature made from another branch is not a release.
IDENTITY='https://github.com/rancher/suse-security-policies/.github/workflows/repackage-policy.yaml@refs/heads/main'

# The module file attached to the release, against this repository
cosign verify-blob suse-policy.wasm \
  --bundle suse-policy.wasm.bundle.sigstore \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The same module, from the registry
cosign verify ghcr.io/rancher/suse-security-policies/<policy-id>:v<version> \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The upstream claim, against the upstream release workflow at the same tag
cosign verify-blob upstream-policy-sbom.spdx.json \
  --bundle upstream-policy-sbom.spdx.jsonl.bundle.sigstore \
  --certificate-identity 'https://github.com/kubewarden/policies/.github/workflows/release.yml@refs/tags/<policy-name>/v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The SUSE claim, against this repository
cosign verify-blob policy-sbom.spdx.json \
  --bundle policy-sbom.spdx.jsonl.bundle.sigstore \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The same document, from the registry
cosign verify-attestation ghcr.io/rancher/suse-security-policies/<policy-id>:v<version> \
  --type spdxjson \
  --certificate-identity "$IDENTITY" \
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

`force` deletes the existing release and its tag, and then creates them again.
`force` requires `policy-name`. Thus one run cannot republish every policy.

Run each command above on `main`. Without `--ref`, `gh workflow run` uses
`main`. A run on another branch fails.

## Configuration

The file [`config.yaml`](config.yaml) contains all the values that depend on
the environment:

- The upstream repository and registry.
- The expected signer identity.
- The destination registry.
- The SUSE metadata and the SBOM values.
- The pinned tools.
- The list of excluded policies.

To move to a different registry, change `config.yaml` and the registry login
step. No other change is necessary.

### Updating the pinned tools

`config.yaml` pins `kwctl` and `sbom-utility` by version and by sha256.
Renovate does not update them. A new version without the matching checksum
gives pull requests that always fail. To update a tool, change the version and
the checksum together. The `kwctl` releases are on the
[adm-controller releases](https://github.com/kubewarden/adm-controller/releases)
page. `sbom-utility` publishes no sha256 file, so you must compute the
checksum from the released archive.

`kwctl annotate` writes the version of `kwctl` into the module. Thus a new
`kwctl` version changes the `io.kubewarden.kwctl` annotation of all later
releases. That annotation is on the allowlist, so this change is expected.

### Keeping the excluded list in sync

`excluded_policies` is a copy of `EXCLUDED_FROM_PUBLISHING` in the upstream
release workflow. Upstream builds those policies but does not publish them,
because they are demos and test fixtures. If upstream changes that list,
change `config.yaml` to match.

## Scripts

| Script | Purpose |
|---|---|
| `hack/discover-releases.sh` | Decide which upstream releases still need repackaging |
| `hack/annotation-args.sh` | List the provenance annotations kwctl patches in for SUSE |
| `hack/check-upstream-metadata.sh` | Fail if the verified module is not the release being repackaged |
| `hack/check-metadata-diff.sh` | Fail if anything outside the allowlist changed |
| `hack/check-repackaged-metadata.sh` | Fail if the result does not carry the new metadata |
| `hack/generate-sbom.sh` | Build the SUSE SPDX document for the repackaged artifact |
| `hack/verify-sbom.sh` | Fail if that document does not match the files being released |
| `hack/render-changelog.sh` | Build the release notes from the upstream changelog |

The scripts read `config.yaml` and take their inputs from environment
variables. Thus you can run them on your computer.

## kwctl requirements

The workflow needs kwctl 1.39 or later. That version of `kwctl annotate` has
two behaviors:

- It removes every existing metadata section before it writes the new section.
- Without `--metadata-path`, it adds each `--annotation KEY=VALUE` pair to the
  metadata that is already in the module.

The workflow uses the second behavior. It changes only the provenance
annotations that `hack/annotation-args.sh` lists. It never exports the rest of
the metadata and never reads it back. `hack/check-metadata-diff.sh` and
`hack/check-repackaged-metadata.sh` make sure that nothing else changed and
that the result contains the new values.

The configuration pins kwctl to `v1.39.0-rc.1`, the first build with these
behaviors. When the stable `v1.39.0` release is available, change the pin to
that release.

## Known limitations

- All releases of a policy point at the same commit of the default branch,
  because this repository contains no policy source. Thus a tag identifies
  only a version, not a source state.
- After a failure, the clean-up deletes registry content through the GitHub
  packages API with the workflow token. This works only for packages that give
  admin access to the repository. GHCR gives that access for packages that the
  workflow created. If the API refuses the request, the run logs an error with
  the digest. Then you must delete the digest by hand.
- The pipeline does not prove that the bytes outside the metadata section are
  the same as upstream. `kwctl annotate` writes the whole module out again,
  and the upstream module went through a different kwctl version. Two changes
  can close this gap. The first is a step that removes the metadata section
  from both modules and compares the sha256 of the results. The second is an
  annotation step that writes the section without a new emit of the module.

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
- The upstream SBOM signature is verified before the SBOM is adapted and
  re-signed. A missing or unverifiable SBOM fails the release.

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
       verify + adapt + re-sign the SBOM
       push and sign in the destination registry
       verify our own signature
                          |
                          v
          GitHub release in this repository
          + signed artifact in the private registry
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
destination registry, the SUSE metadata values and the excluded policy list.

Moving to a different registry later means editing `config.yaml` and the
registry login step, nothing else.

### Updating kwctl

`kwctl` is pinned by version **and sha256** in `config.yaml`. Renovate does not
manage it, because bumping the version without the matching checksum would
produce pull requests that always fail. To upgrade, update both fields together
from the
[kubewarden-controller releases](https://github.com/kubewarden/kubewarden-controller/releases).

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
| `hack/adapt-sbom.sh` | Rewrite SPDX document provenance |
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

- **The SBOM describes upstream source, not our artifact.** Upstream generates
  it with `syft` over the policy source tree, which we do not have. We adapt
  the document level provenance and re-sign it, but the package list is still
  the one upstream produced. The sha256 of the original document is recorded in
  the SPDX `comment` field so the chain stays auditable.
- **Patching the SBOM breaks digest equality with upstream.** That is
  unavoidable once content changes; the recorded upstream hash is what
  preserves the link.
- Releases of the same policy all land on the same commit of the default
  branch, because this repository holds no policy source. The tags are
  therefore meaningful only as version markers.

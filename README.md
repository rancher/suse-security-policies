# SUSE Security Policies

This repository republishes the Kubewarden policies of
[kubewarden/policies](https://github.com/kubewarden/policies) under the SUSE
identity, into a private OCI registry.

The repository contains no policy source code, and this repository compiles
nothing. The upstream project builds and signs a WebAssembly module for each
policy. The CI of this repository takes that module and makes sure that its
signature is valid. Then it changes the provenance metadata of the module.
Provenance is the record of where an artifact comes from. Last, the CI signs
the result with the identity of this repository and publishes it.

Report policy bugs and feature requests upstream. Report only packaging,
signing and distribution problems here.

## Requirements

To run the repackage process, you need:

- Linux on x86_64.
- Go 1.27.2.
- `make`, `curl`, `tar`, `unzip` and `sha256sum`.
- kwctl v1.39.0-rc.1. You need kwctl 1.39 or later, because older versions
  of `kwctl annotate` cannot change single annotations.
- cosign v3.1.3.
- sbom-utility v0.19.2.
- gh v2.102.0.
- Docker credentials that can read the upstream registry and write the
  destination registry.
- A GitHub token with write access to this repository, for a real run.

The command `make runtime-tools` installs the pinned versions of kwctl,
cosign, sbom-utility and gh into `bin/`.

## The repackager command

A Go program, `repackager`, does all the work. Its source code is in
`cmd/repackager`. It runs `gh`, `kwctl`, `cosign` and `sbom-utility` for each
step, and reads their output. It has three commands:

- `check-config` makes sure that `config.yaml` has every value that the
  pipeline needs.
- `discover` lists the latest upstream release of each policy that has no
  published release in this repository yet.
- `repackage` repackages one policy version, and signs and publishes it.

The workflow `.github/workflows/sync-upstream-releases.yaml` runs the program
through `make discover` and `make repackage`. The `discover` job finds the
releases. Then the workflow runs one `repackage` job for each policy. A person
starts the workflow by hand. Only the `main` branch can publish.

### The steps

The `repackage` command runs these steps in this order:

1. Find the upstream release. If this repository already has a published
   release for the version, the command runs only the step "Verify the
   published release". If the tag exists without a published release, the
   command stops.
2. Verify the upstream policy signature. The signer identity names the exact
   release tag. Later steps use the digest from the signed payload, so a tag
   that moves during the run changes nothing. A digest is the sha256 hash
   that identifies one artifact.
3. Annotate the policy. `kwctl annotate` changes only the annotations on an
   allowlist. The command makes sure that no other metadata changed.
4. Download and verify the upstream SBOM. An SBOM (software bill of
   materials) is a list of what an artifact contains.
5. Download the upstream source archive of the commit that the upstream SBOM
   names.
6. Validate a draft of the SUSE SBOM, with a placeholder digest.
7. Push the repackaged policy to the destination registry.
8. Generate the SUSE SBOM with the digest of the pushed artifact.
9. Render the release notes.
10. Sign and attest. An attestation is a signed statement that the registry
    stores next to the artifact.
11. Publish the release.

The command pushes nothing before step 7 and signs nothing before step 10.
With `--dry-run`, it runs every step that only reads, and it pushes, signs and
publishes nothing. The command gets its signing identity from the
`GITHUB_WORKFLOW_REF` variable. That variable must name a workflow file of
this repository on the `main` branch, or the command stops before it signs.

Each release contains two SBOMs. The upstream SBOM is the file that upstream
signed, without changes, so its signature stays valid for the upstream
identity. The SUSE SBOM describes the module that SUSE publishes. It
records the sha256 and the OCI digest of the module, and it refers to the
upstream SBOM. The command signs the SUSE SBOM and attests it to the pushed
artifact.

### Idempotency

Idempotency means that a second run of the same release is safe and finishes
the work of a failed run. The command saves no state on disk. It finds the
results of an earlier run in the registry and on GitHub:

- If the tag of the version is already in the registry, the command reuses
  the artifact only if the module bytes are equal to its own module.
  Otherwise it stops. It never moves a tag.
- If a signature or an attestation of an earlier run is valid for the
  identity of this repository, the command keeps it. It signs only when cosign reports that no matching
  signature exists. Any other error stops the run.
- If the registry has an SBOM attestation that differs from the SUSE SBOM of
  the release, the run stops before it publishes.
- The command tries each read up to three times. It never tries a write
  again.
- The command uploads the assets to a draft release, makes sure that the
  draft is correct, and publishes it by its id. After the publication, it
  reads the release again and makes sure that it is still correct.
- The command deletes the old drafts for the tag only after the publication.
- If the release is already published, the command makes sure that the
  release and the registry artifact are correct, and passes.

## Configuration

The file [`config.yaml`](config.yaml) holds the values that depend on the
environment: the upstream repository and the signer identity, the destination
registry, the SUSE metadata and SBOM values, and the excluded policies. The
comments in the file explain each value. The CI runs `make check-config` on
each pull request to make sure that no value is missing.

## Known limitations

- Before you use the workflow, enable immutable releases in the settings of
  the repository. The workflow does not enable them.
- The workflow does not run by itself. A person must start it to find and
  publish new upstream releases.
- The workflow reports a failure only as a failed job. Nobody gets a message
  unless they watch the workflow runs.
- If the command finds a problem in the release after the publication, the
  release stays as it is, because it is immutable. The job fails, and you must fix the release by
  hand.
- A failure in step 7 or later can leave the artifact in the registry, so a
  tag can be visible before its release exists. The next run reuses it only
  if it builds the same module. If you change the kwctl version between the
  two runs, the module changes, and you must delete the artifact by hand.
- If the tag of a version exists without a published release, the workflow
  does not publish that version. A repository with immutable releases cannot
  use that tag again. A newer upstream version gets its release as usual.
- The tests cannot reach GHCR. Before the first run in the `rancher`
  organization, make sure by hand that a package that `GITHUB_TOKEN` creates
  links to this repository. Also make sure that `notFoundPattern` in
  `cmd/repackager/repackage.go` matches the exact "not found" error of GHCR.
  Otherwise a run can stop after the push and before the signature.
- The pipeline does not prove that the bytes outside the metadata section are
  the same as upstream. `kwctl annotate` writes the whole module out again.
- The tag of a release points at the commit of this repository that built
  the release, not at a source state of the policy. The release notes name
  the upstream source commit.

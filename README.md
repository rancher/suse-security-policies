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

- The published module comes from the upstream module. The workflow pulls it by
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
  Upstream signs in two formats: the legacy format and the v3 bundle format.
  The signatures in both formats must verify.
- The workflow takes the digest from the payload that upstream signed. Every
  later step uses that digest. If somebody moves the tag during the run, the
  artifact does not change.
- The metadata inside the module must name the policy id and the version of
  the release. Discovery reads those values from git. This check makes sure
  that git and the module agree.
- Only the annotations on an allowlist can change. A change to `rules`,
  `mutating`, `contextAware`, `executionMode` or the policy version stops the
  build.
- The `io.kubewarden.policy.source` annotation keeps the upstream value. It
  tells where the source code is, and this repository contains no source code.
  A change to this annotation stops the build.
- The `io.kubewarden.policy.author` annotation names SUSE, the publisher. The
  `com.suse.policy.upstream.author` annotation keeps the upstream author.
- The workflow signs the repackaged module two times with the identity of this
  repository. One signature is on the OCI artifact in the registry. The other
  signature is a bundle in the format of `cosign sign-blob`. It is on the
  `suse-policy.wasm` file on the release page. The workflow checks both
  signatures before it creates the release.
- Only the `main` branch publishes. A run from another branch stops before
  discovery. This is also true for a dry run. The `repackage` job has write
  permissions and `id-token: write` in a dry run too, because GitHub Actions
  cannot set permissions from an input. The program gets the signing identity
  from the `GITHUB_WORKFLOW_REF` variable that GitHub Actions sets. This
  variable must name a workflow file of this repository on the `main` branch.
  Otherwise the program stops before it signs anything. The identity is
  `https://github.com/` followed by this value, for example
  `https://github.com/rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main`.
  The workflow checks every signature that it makes against this exact
  identity. A signature from another branch fails that check.
- The signing job is in `sync-upstream-releases.yaml`, not in a reusable
  workflow. The signing certificate names the workflow file that holds the
  job. Any repository can call a reusable workflow of a public repository, and
  the caller checks out its own code. Thus a reusable workflow would let
  another repository sign with the identity of this repository.
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
  signed statement that the registry stores next to the artifact.
  `sbom-utility` makes sure that the SUSE SBOM is valid SPDX 2.3, one time
  before the push and one time after the push.
- The workflow signs nothing until every check that can run before the
  release passes.
- The workflow pushes the module only after every check passes that only
  reads and that does not need the pushed artifact. These checks include the
  upstream signature, the module metadata, the upstream SBOM, the source
  commit and a draft of the SUSE SBOM. If one of them fails, the run stops
  and puts nothing in the registry.
- A failed run deletes no artifact in the registry and no release. The
  release step creates a new draft release. It deletes the old drafts for the
  tag only after the publication. If a run fails, a person must look at the
  failure, fix the cause and start the workflow again. See
  [When a run fails](#when-a-run-fails).
- The workflow never moves an OCI tag. If the tag of a version is already in
  the destination registry, the run compares the module under the tag with
  its own module. If they are the same, an earlier run pushed it, and the run
  reuses the artifact. If they differ, the run stops.
- Before it pushes anything, the run looks for the release of the version.
  If the release is already published, the run does not repackage the policy.
  It only reads the published release and makes sure that it is correct. See
  [Running a release again](#running-a-release-again). If the tag of the
  version exists without a published release, the run stops.
- The releases of this repository are immutable. After the publication, nobody
  can change the assets or the tag of a release. Thus the workflow uploads the
  assets to a draft release, and only then publishes the release.
- Before the publication, the program reads the draft by its id. It checks
  the tag, the commit, the names of the 7 assets, and the state, size and
  sha256 digest of each asset. It also checks that the tag does not exist and
  that no published release has the tag. After the publication, it reads the
  release again and makes the same checks. It also makes sure that the tag
  points at the commit of the run. GitHub can show the new release a little
  later. This check runs up to 3 times, with a wait of 2 and then 8 seconds
  between the tries.
- GitHub cannot check and publish a release in one step. A person or a token
  with write access to the repository can change the draft or push the tag
  between the check and the publication. The program finds such a change
  after the publication, but it cannot prevent it. Thus give write access to
  the repository only to the people and tools that need it.

## How it works

A Go program, `repackager`, does all the work. It runs `gh`, `kwctl`,
`cosign` and `sbom-utility` for each step, and reads their JSON output. Its
source code is one Go package in `cmd/repackager`:

| File | Contents |
|---|---|
| `cli.go` | The commands and the flags |
| `main.go` | The start of the program and the GitHub Actions logging |
| `exec.go` | The function that runs a tool, and helpers that read JSON |
| `config.go` | The configuration |
| `discover.go` | The `discover` command |
| `repackage.go` | The steps of the `repackage` command |
| `sbom.go` | The SUSE SBOM |
| `notes.go` | The release notes and the job summaries |

The workflow `.github/workflows/sync-upstream-releases.yaml` calls targets of
the `Makefile`. These targets build the program from the commit of the run
and run it.

```
                 kubewarden/policies
                   releases + GHCR
                          |
   (1) discover           v
   manual start ---> sync-upstream-releases.yaml
                          |  matrix of policies without a release here
                          v
   (2) repackage job, one for each policy
                          |
       check that the release is not published
       find the upstream release: tag, address, policy id
       verify upstream signature (pinned to the tag)
       pull by digest
       check the module metadata names the release
       patch the provenance annotations in place
       check nothing else moved
       verify the upstream SBOM, which the release republishes
       check the upstream tag names the commit in the upstream SBOM
       download the upstream source archive of that commit
       generate and validate a draft SUSE SBOM with a placeholder digest
       push to the destination registry, unsigned, or reuse the same module
       generate and validate the SUSE SBOM with the pushed digest
       render the release notes
       sign the artifact, the module file and the SUSE SBOM
       attest the SUSE SBOM, verify our own signatures
       create a draft release, upload the assets
       check the draft, publish it by its id, check the release again
       delete the old drafts for the tag
       on failure: the job fails
                          |
                          v
          GitHub release in this repository
          + signed artifact and SBOM attestation in the private registry
```

The workflow has two jobs: `discover` and `repackage`.

For now, the workflow runs only when a person starts it by hand
(`workflow_dispatch`). It has no schedule. The inputs are `policy-name`,
`policy-version` and `dry-run`.

### 1. Discovery: the `discover` job

The discovery job runs `repackager discover`. The command lists the upstream
releases and keeps the highest version of each policy. It removes
prereleases and the policies that upstream does not publish. Then it removes
each release that already has a published release in this repository. If a
person gives `policy-version`, the command keeps a published release. The
`repackage` job then verifies it. See
[Running a release again](#running-a-release-again).

The command also reads the tags of this repository one time. A tag can exist
without a published release, for example after someone deleted an immutable
release or pushed the tag by hand. The `repackage` job stops at such a tag.
Thus the command skips that version with a warning that names the tag. A
person must check the tag. The other policies go on. When a person asks for
one policy by name, this tag stops the discovery with an error instead.

A published GitHub release in this repository is the only record that a
version is published. A draft release does not count.

For each release that is left, the command reads the policy id from the
upstream `metadata.yml` at the tag. It checks the release with the same rules
as the repackaging job: the policy id and the version `X.Y.Z`. The metadata
must name the version of the tag. The command ignores a tag whose policy name
cannot be a part of a file path. If one release fails these checks, the
command skips it with a warning that names the tag and the reason. The other
policies go on. When a person asks for one policy by name, the problem stops
the discovery with an error instead.

The program uses `gh` to read data from GitHub. If `metadata.yml` does not
exist at the tag, GitHub answers with HTTP 404. Then the command skips the
release with a warning, like for the other checks. Each other failure of
`gh` stops the discovery, because it can hide any release. The `repackage`
command reads `metadata.yml` in the same way, but each failure stops it.

The workflow publishes only the latest version of each policy. It does not
publish older versions, unless a person asks for one by hand.

### 2. Repackaging: the `repackage` job

The repackaging job runs one time for each policy version that the discovery
job finds. It runs only on the `main` branch. The job gets the policy name
and the version from the matrix of the discovery job. It has one step,
`make repackage`, which runs `repackager repackage`. The command runs these
steps in one process. Each step is a log group:

1. Find the upstream release. The step first reads the release of the tag in
   this repository. If the release is published, the run skips steps 2 to 11.
   It runs the step "Verify the published release" instead. See
   [Running a release again](#running-a-release-again). If the release is not
   published, the step makes sure that its tag does not exist. Then it finds
   the upstream release of the policy name and the version, and it makes the
   same checks as the discovery. It reads the policy id from the upstream
   `metadata.yml` at the tag.
2. Verify the upstream policy signature.
3. Annotate the policy.
4. Download and verify the upstream SBOM. The step also reads the
   publication time of the upstream release.
5. Download the upstream source archive. The step first makes sure that the
   upstream tag points at the commit that the upstream SBOM records.
6. Validate a draft of the SUSE SBOM. The draft has a placeholder digest,
   because the module is not pushed yet.
7. Push the repackaged policy.
8. Generate the SUSE SBOM. The step builds it with the digest of the pushed
   artifact and validates it again.
9. Render the release notes.
10. Sign and attest. The step also verifies every signature.
11. Publish the release. The step creates a draft release through the GitHub
    API and uploads the assets to it. Then it reads the draft by the id in the
    response to the creation. It checks the tag, the commit, the names of the 7
    assets, and the state, size and sha256 digest of each asset. It also checks
    that the tag does not exist and that no published release has the tag. If a
    check fails, the draft stays and the step stops. Next, it publishes that
    draft by its id. It does not look for the draft by its tag, because another
    draft can have the same tag. Then it reads the release again and makes the
    same checks. It also makes sure that the tag points at the commit of the
    run. Last, if these checks pass, it deletes the old drafts for the tag.

The program pushes nothing before step 7 and signs nothing before step 10.
Steps 1 to 6 change nothing in the registry or on GitHub. The SUSE SBOM and
the release notes record the digest of the pushed artifact, so steps 8 and 9
come after the push. If a step fails, the job fails and the later steps do
not run. See [When a run fails](#when-a-run-fails).

The steps share their results in memory. The program saves no state file.
It writes the files of the run to a temporary directory and removes the
directory at the end. With `--work-dir`, it writes the files to that
directory and keeps them, for example to look at them after a failure.

This design has a cost. One workflow step runs all steps of the program. The
log shows each step as a group in that workflow step. One time limit applies
to all of them. In return, no step can read the state of another release or
of an earlier run. A second run finds the results of an
earlier run in GitHub and in the registry, not on disk. See
[Running a release again](#running-a-release-again).

### 3. Dry run

A person can start the workflow with the `dry-run` input. Then the
`repackage` job passes `DRY_RUN=true` to `make repackage`, which runs
`repackager repackage --dry-run` for each release.

A dry run reads everything that a real run reads, and it runs every check
that only reads. It pushes nothing, signs nothing and creates no release.
The job keeps its write permissions and `id-token: write`, because GitHub
Actions cannot set permissions from an input. Thus a dry run also runs only
on the `main` branch.

A dry run makes sure that a draft of the SUSE SBOM is valid. The draft has a
placeholder digest. A dry run cannot make the SUSE SBOM of a module that is
not in the registry yet. The SUSE SBOM records the digest of the pushed
artifact, and a dry run does not push.

## The repackager program

| Command | What it does |
|---|---|
| `check-config` | Fails if `config.yaml` misses a value that the pipeline needs |
| `discover` | Prints the releases that still need a repackaging, as a JSON list. In GitHub Actions it also sets the outputs `matrix` and `count` and writes the job summary |
| `repackage` | Repackages one policy version: it verifies, annotates, pushes, signs and publishes it. It stops at the first failure and returns the error. For a published release, it only verifies the release |

Flags:

| Flag | Commands | Meaning |
|---|---|---|
| `--config` | all | Path of the config file. The default is `config.yaml` |
| `--repository` | `discover`, `repackage` | Required. `owner/repo` of this repository |
| `--sha` | `repackage` | Required. Commit of this repository that runs the pipeline |
| `--policy-name` | `discover`, `repackage` | Required for `repackage`. The name of the upstream policy, for example `pod-privileged-policy`. For `discover`, it finds only this policy |
| `--policy-version` | `discover`, `repackage` | Required for `repackage`. The version without the `v` prefix, for example `1.0.13`. For `discover`, it needs `--policy-name`, and it keeps a published release, so that `repackage` verifies it |
| `--dry-run` | `discover`, `repackage` | `repackage` pushes, signs and publishes nothing, but runs every check that only reads. `discover` marks the job summary as a dry run |
| `--work-dir` | `repackage` | Keep the files of the run in this directory. Without it, the program uses a temporary directory and removes it at the end |

A required flag must not be empty. The program reads no flag value from the
environment. It reads only these environment variables:

| Variable | Meaning |
|---|---|
| `GITHUB_OUTPUT` | The file of the step outputs. GitHub Actions sets it. Without it, `discover` writes no outputs |
| `GITHUB_STEP_SUMMARY` | The file of the job summary. GitHub Actions sets it. Without it, the program writes the summary to the log or to stdout |
| `GITHUB_WORKFLOW_REF` | The workflow that runs the program, for example `rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main`. GitHub Actions sets it. `repackage` signs and verifies with the identity `https://github.com/` followed by this value. Without `--dry-run`, `repackage` stops before the first step if the variable is not set or does not name a workflow file of this repository on the `main` branch |

The temporary directory follows `TMPDIR`. The tools that the program runs get
the whole environment. `GH_HOST`, `GH_REPO`, `GH_FORCE_TTY`, `CLICOLOR_FORCE`
and `GH_PAGER` change the behavior of `gh`. The program passes
`--hostname github.com` to each `gh api` call, so `GH_HOST` cannot send the
requests to another host.

The program runs `gh api` for each GitHub call. `gh` needs a token. It reads
`GH_TOKEN` or `GITHUB_TOKEN`, or the login of `gh auth login`. The drafts, a
private repository and every write need a token with write access. `gh`
changes the control characters in each JSON response, for example in the
upstream release notes, and the program accepts this change.

The program runs `kwctl`, `sbom-utility`, `cosign` and `gh`. It finds them
on the `PATH`. The program does not make sure that a tool is installed
before the run. A missing tool stops the run at the first step that needs
it. The targets `make discover` and `make repackage` put `bin/` first on the
`PATH`. Thus the tools that `make runtime-tools` installs into `bin/` come
before other copies. In the CI, the installer actions install kwctl and
cosign. `make sbom-utility` installs sbom-utility, and `make gh` installs gh.
The runner image also has a gh, but its version can change without review.
`kwctl` and `cosign` use the Docker credentials of the computer to
read and write the registries. They read `DOCKER_CONFIG`.

The program runs `cosign` to sign and to verify. To sign, `cosign` gets an
ID token from GitHub Actions. It reads `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which GitHub Actions sets only for a job
with the permission `id-token: write`. The program itself does not read these
variables. The program does not read the registry itself. It runs `kwctl`
and `cosign` for each read.

### Running a release again

A run is safe to repeat. A step that leaves something behind first checks
whether an earlier run did it already. Then it reuses the result:

- Push: if `kwctl pull` finds the tag of the version in the destination
  registry, the program gets the digest of the tag with `kwctl digest`. It
  pulls the module by that digest and compares the sha256 of that module
  with the sha256 of the module that it built. If they are the same, an
  earlier run pushed it, and the program reuses the artifact. If they
  differ, the run stops. The program never moves an OCI tag.
- Signatures: before it signs the artifact in a format, the program runs
  `cosign verify` for the legacy format, and `cosign verify-attestation
  --type https://sigstore.dev/cosign/sign/v1` for the v3 bundle format,
  with the identity of this repository. If the check passes, the program
  keeps the signature of the earlier run and does not sign again. If
  cosign reports that no matching signature exists, the program signs. Any
  other error, for example a network error, stops the run before it writes
  to the registry. The same rule applies to the SBOM attestation, which
  `cosign verify-attestation --type spdxjson` checks. The program runs all
  these checks before it signs.
- Signature bundles: a bundle is the file that holds the signature of a file
  on the release page. The program always signs the module file and the SUSE
  SBOM again.

The program generates the SUSE SBOM again in each run. If the attestation of
an earlier run verifies, the program keeps it. The SBOM does not record the
commit of `--sha`, so a run from another commit gives the same SBOM for the
same artifact. The program checks the SBOM attestation before it signs, and
it compares the SBOM in each attestation of this repository with the SBOM of
the release. If one or more attestations differ, the run stops before it
writes to the registry.
This happens when an earlier run used another version of the program, for
example one that wrote another tool name into the SBOM.

If the check after signing finds a stale attestation, the new attestation
stays in the registry, and the run stops before it publishes. A short
registry error can still hide an old SBOM attestation from the first check.
Then the run attests again, and the check after signing stops the run
before it publishes.

A stale SBOM attestation does not go away by itself. A person must delete it
in GHCR and then start the run again:

1. Find the digest of the attestation. Run `cosign tree` on the artifact
   reference from the error. The attestation is the line that shows
   `https://spdx.dev/Document artifacts via OCI referrer`, followed by the
   reference and digest of the attestation.

   ```sh
   cosign tree ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:<artifact digest>
   ```

2. Find the package version whose name is that digest. In the package name,
   write the `/` as `%2F`. For a package of a user account, use
   `/user/packages/...` instead of `/orgs/rancher/packages/...`.

   ```sh
   gh api --paginate /orgs/rancher/packages/container/suse-security-policies%2Fpod-privileged/versions \
     --jq '.[] | select(.name == "sha256:<attestation digest>") | .id'
   ```

3. Delete that version:

   ```sh
   gh api -X DELETE /orgs/rancher/packages/container/suse-security-policies%2Fpod-privileged/versions/<id>
   ```

4. Start the workflow again for the release.

The deletion removes the attestation from the registry only. Its entry in
the public Rekor transparency log stays, because nobody can delete a Rekor
entry.

If the release of the version is already published, the run does not
repackage the policy. It runs one step, "Verify the published release". The
step only reads, so a dry run does the same. It downloads the 7 assets of the
release to the `published` directory in the work directory, and it makes
these checks:

- The release is not a draft, has the tag, and has exactly the 7 assets. Each
  asset is uploaded and has a sha256 digest.
- The tag points at the commit of the release. A release of an earlier run
  has the commit of that run, so the step does not compare it with `--sha`.
- The sha256 of each downloaded asset is equal to the digest of the asset.
- The bundles of the module and of the SUSE SBOM verify with the identity of
  this repository. The bundle of the upstream SBOM verifies with the upstream
  identity.
- `kwctl digest` gives the digest of the tag of the version in the
  destination registry. The module that `kwctl pull` gets by that digest is
  equal to the module of the release.
- The legacy signature, the v3 bundle signature and the SBOM attestation of
  that digest verify with the identity of this repository. The attested SBOM
  is equal to the SUSE SBOM of the release.
- The SUSE SBOM of the release records the sha256 of the module and the
  sha256 of the upstream SBOM of the release. Its purl names the registry
  digest.

A new run cannot make the source archive and the bundles again with the same
bytes. Thus the step does not compare them with a new build. It uses the
digests and the signatures of the release. The source archive has no
signature, so it gets only an integrity check: its sha256 must be equal to
the digest that GitHub records for the asset. This check shows only that the
download is complete. The step needs `GITHUB_WORKFLOW_REF` for the identity of this
repository, also in a dry run. If every check passes, the job passes, and the
job summary says that the run verified the published release. If a check
fails, the job fails, and the job summary lists the failures. The release is
immutable, so a person must check it by hand.

Without `policy-version`, the `discover` job skips each published release.
Thus the step runs in these cases:

- A person starts the workflow with `policy-name` and `policy-version`.
- A person runs the failed `repackage` job again with "Re-run failed jobs".
  The new attempt uses the matrix of the first attempt.
- Another run published the release after the `discover` job of this run.
- A person runs `repackager repackage` by hand.

The draft releases of failed runs stay until a run publishes the release.
A draft of a failed run does not stop the next run. After the publication
and its checks, the run deletes the old drafts for the tag. Before each
delete, it reads the release again, and it deletes the release only if it is
still a draft. The run does not delete a draft before the publication. At
that time, a person can publish an old draft between the list and the
delete. Then the run deletes a published release, and nobody can use its tag
again.

If GitHub answers that an old draft does not exist, the run counts it as
deleted. If the run cannot delete an old draft, the job still passes,
because the release is published and correct. The log shows a warning, and
the job summary says that the run cannot delete one or more old drafts for
the tag. Then a person must delete them by hand.

### When a run fails

The releases of this repository are immutable. A second try can fail again
or publish a wrong result. Thus the workflow does not try a failed release
again by itself. A failed step stops the job, and the job fails with an
error in the log. A failed run deletes no artifact in the registry and no
release. The draft release of a failed run and the artifact stay for the
next run.

A failed read can come from a short network error, for example a GitHub
502, a registry 5xx, a Rekor timeout or a rate limit. GitHub sends a rate
limit as HTTP 429, or as HTTP 403 with "rate limit" in the message. Thus the
program tries each read up to three times. It waits 2 seconds before the
second try and 8 seconds before the third try. The log shows a warning
before each new try. The reads are the GET calls of `gh api`, and the
commands `gh release download`, `kwctl pull`, `kwctl digest`, `cosign
verify`, `cosign verify-attestation` and `cosign verify-blob`. A read can run
again without risk, because it changes nothing.

The program does not try a read again when the answer cannot change. These
answers are a GitHub 4xx error that is not a rate limit, a tag that is not
in the registry, and a cosign result that shows no signature or attestation
from the expected signer. cosign returns the same error for a bad signature
and for a network error. Thus a bad signature fails three times before the
job fails.

The program never tries a write again. The writes are the `gh api` calls
that create, upload, publish or delete, `kwctl push`, `cosign sign`,
`cosign attest` and `cosign sign-blob`. A write that failed can still have
changed the registry or the release, and the releases are immutable. If a
write fails, the job fails, and a person must look at the result before
they start the workflow again.

If a check of the draft fails before the publication, the run publishes
nothing. The draft stays for a person to look at. The run that publishes the
release deletes it.

If the check of the release after the publication fails, the run fails too.
This check also covers the download address. The release is published and
immutable then, so a person must check it and fix it by hand. The job
summary also says that the check failed. The run does not delete the old
drafts for the tag then, so a person must also delete them by hand.

The call that publishes the release can fail after GitHub published the
release, for example when the connection breaks or GitHub loses the runner.
Then the program does not read the release again, and the job fails. A person
can start the workflow with `policy-name` and `policy-version`, or run the
failed job again with "Re-run failed jobs". The new run finds the published
release and verifies it. If every check passes, the job passes.
If a check fails, a person must check the release by hand. See
[Running a release again](#running-a-release-again).

To try a failed release again:

1. Read the log of the failed workflow run.
2. Look at the draft release for the tag, if there is one. If it is
   incomplete, you can delete it. The run that publishes the release also
   deletes it.
3. Look at the artifact in the destination registry, if there is one. Make
   sure that it is correct, or delete it. For example, delete it if the
   run stopped because the tag holds another module.
4. Fix the cause of the failure.
5. Start the workflow again by hand. The next run reuses the pushed
   artifact, the signatures and the SBOM attestation.

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

The program writes the SUSE document. The document is a distribution
record, not a scan. It contains one package, which describes
`suse-policy.wasm` and nothing else. The document records these items:

- The sha256 of the module and the `pkg:oci` purl of the pushed manifest. A
  purl is a package URL. These two values tie the document to the bytes that
  SUSE publishes. The purl has this form:
  `pkg:oci/<policy-id>@sha256%3A<hex>?repository_url=<registry>/<policy-id>&tag=v<version>`.
- `supplier: SUSE` and `originator: Kubewarden`. SPDX uses these two fields to
  separate the party that distributes an artifact from the party that made it.
- The upstream repository, the release tag, the OCI digest and the source
  commit, in `sourceInfo`. `sourceInfo` also names the annotations that
  `kwctl annotate` set. It says that the program made sure that no other
  metadata changed, except the `io.kubewarden.kwctl` annotation, and that the
  program did not compare the other bytes of the module.
- The license fields, copied from the root package of the upstream document.
  SUSE does not state its own license conclusion.
- An `externalDocumentRefs` entry. It names the upstream document by its
  namespace and ties it to the document by its sha256. A `GENERATED_FROM`
  relationship points into the upstream document.

The last two items replace the old method, which changed the upstream
document. The SPDX specification defines this type of reference, and tools can
follow it. The old method used a sentence in a comment field.

The document namespace ends with a UUID that comes from the digest of the
pushed artifact. Thus a new artifact gets a new namespace, and a second run
for the same artifact gets the same namespace.

The workflow signs the SUSE document in the format of `cosign sign-blob`. It
also attests the document to the pushed manifest, in the format of
`cosign attest --type spdxjson`.
Kubewarden pulls policies from the registry, not from GitHub releases. Without
the attestation, tools that use the module cannot find the SBOM.

Before the push, the program builds a draft of the document in
`draft-policy-sbom.spdx.json` in the work directory. The draft has the
placeholder digest `sha256:` followed by 64 zeros. `sbom-utility` makes sure
that the draft is valid SPDX 2.3. The license, copyright and SPDXID fields
come from upstream, so they can make this check fail for every run of a
release. Thus the check runs before the push, also in a dry run. The draft
is not a release asset.

After the push, the program builds the document again with the digest of the
pushed artifact. Before the workflow signs anything, `sbom-utility` makes sure
that this document is valid SPDX 2.3 too. The program builds each field from
the files of the run, so it does not compare the fields with the files again.

`downloadLocation` names the release asset. GitHub builds that address from
the repository, the release tag and the asset name. After the publication,
the program makes sure that the release has an asset at that address. If
this check fails, the run fails. The release is immutable then, so a person
must fix it by hand.

The program checks the signature and the attestation after it signs. It
also makes sure that the SBOM in each attestation of this repository is
equal to the SUSE SBOM file of the release. See
[Running a release again](#running-a-release-again).

### Verifying a release

These examples use the cosign CLI. Install it to run them. The repackager
runs the same checks before it creates the release.

```sh
# Every signature this repository makes carries this identity. Do not accept
# a looser pattern: a signature made from another branch is not a release.
IDENTITY='https://github.com/rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'
REF='ghcr.io/rancher/suse-security-policies/<policy-id>:v<version>'

# The module in the registry, legacy signature format
cosign verify "$REF" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  --new-bundle-format=false

# The module in the registry, v3 bundle format. The type selects the
# signature, so the SBOM attestation cannot stand in for it.
cosign verify-attestation "$REF" \
  --type https://sigstore.dev/cosign/sign/v1 \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"

# The module file attached to the release, against this repository
cosign verify-blob suse-policy.wasm \
  --bundle suse-policy.wasm.bundle.sigstore \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"

# The upstream claim, against the upstream release workflow at the same tag
cosign verify-blob upstream-policy-sbom.spdx.json \
  --bundle upstream-policy-sbom.spdx.jsonl.bundle.sigstore \
  --certificate-identity 'https://github.com/kubewarden/policies/.github/workflows/release.yml@refs/tags/<policy-name>/v<version>' \
  --certificate-oidc-issuer "$ISSUER"

# The SUSE claim, against this repository
cosign verify-blob policy-sbom.spdx.json \
  --bundle policy-sbom.spdx.jsonl.bundle.sigstore \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"

# The same document, from the registry
cosign verify-attestation "$REF" \
  --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
```

## Running it by hand

### In GitHub Actions

```sh
# Repackage everything that is missing
gh workflow run sync-upstream-releases.yaml

# Repackage a single policy at its latest version
gh workflow run sync-upstream-releases.yaml -f policy-name=pod-privileged-policy

# Repackage a specific, possibly older, version
gh workflow run sync-upstream-releases.yaml \
  -f policy-name=pod-privileged-policy \
  -f policy-version=1.0.13

# Run every check, but write nothing
gh workflow run sync-upstream-releases.yaml \
  -f policy-name=pod-privileged-policy \
  -f dry-run=true
```

You cannot publish a version again. The releases are immutable, and the
workflow does not overwrite an OCI tag. Without `policy-version`, the
`discover` job skips a published release. With `policy-version`, it keeps the
release, and `repackager repackage` verifies it. It publishes nothing. See
[Running a release again](#running-a-release-again).

Run the workflow on `main`. Without `--ref`, `gh workflow run` uses `main`.
A run on another branch fails. This is also true for a dry run.

### On your computer

You need Linux on x86_64, Go, `make`, `curl`, `tar`, `unzip`, and
`sha256sum`. The CI calls the same `make` targets, but it installs kwctl
and cosign with their installer actions. The workflow pins the same versions
as the `Makefile`.

```sh
make build         # writes bin/repackager
make test          # runs the Go tests with the race detector, no network access needed
make fmt-check     # fails if gofmt would change a file
make vet           # runs go vet
make lint          # runs golangci-lint
make actionlint    # checks the workflows, with shellcheck
make check-config  # runs repackager check-config
make mod-check     # fails if go mod tidy would change go.mod or go.sum
make vulncheck     # runs govulncheck, which needs network access
make tools         # installs every tool into bin/
make runtime-tools # installs only kwctl, sbom-utility, cosign and gh into bin/
make sbom-utility  # installs only sbom-utility into bin/
make gh            # installs only gh into bin/
```

A target that needs a tool installs it into `bin/` first. `make` downloads
the release asset, makes sure that its sha256 is the pinned one, and installs
the binary. The file name of each tool has its version, for example
`bin/cosign-<version>`. `make` downloads again only when the file of the pinned
version is missing. Thus a new version installs again, but a new checksum
for the same version does not. The tools are golangci-lint, actionlint,
shellcheck, kwctl, sbom-utility, cosign and gh. Only Linux on x86_64 is
supported. `make` also creates a symlink without the version for each of
kwctl, sbom-utility, cosign and gh, for example `bin/cosign`. The
`repackager` finds the tools on the `PATH` by these names.

The targets call golangci-lint, actionlint, shellcheck and govulncheck by
their paths in `bin/`, which include the version. These `make` variables hold
the paths:

| Variable | Tool |
|---|---|
| `GOLANGCI_LINT` | golangci-lint |
| `ACTIONLINT` | actionlint |
| `SHELLCHECK` | shellcheck |
| `GOVULNCHECK` | govulncheck |
| `KWCTL` | kwctl |
| `SBOM_UTILITY` | sbom-utility |
| `COSIGN` | cosign |
| `GH` | gh |

To see the paths, run `make -n lint actionlint vulncheck runtime-tools`. The
command prints the recipes and does not run them. After a version change,
the file of the old version stays in `bin/`. Delete it by hand.

govulncheck has no release asset. `make` installs the pinned version with
`go install`, and Go makes sure that the module matches the Go checksum
database.

`make vulncheck` fails when govulncheck finds a vulnerability that the code
calls.

The targets `discover` and `repackage` run the `repackager` command of the
same name. The targets read these environment variables and pass them to the
flags:

| Variable | Flag | Targets |
|---|---|---|
| `REPOSITORY` | `--repository` | `discover`, `repackage` |
| `SHA` | `--sha` | `repackage` |
| `POLICY_NAME` | `--policy-name` | `discover`, `repackage` |
| `POLICY_VERSION` | `--policy-version` | `discover`, `repackage` |
| `DRY_RUN` | `--dry-run` | `discover`, `repackage`. Optional. The default is `false` |
| `WORK_DIR` | `--work-dir` | `repackage`. Optional |

The two targets run the `repackager` with `bin/` first on the `PATH`.

The recipes expand each variable in the shell and put it in quotes. Thus
`make` does not change a value, and the shell does not split it.

A dry run on your computer reads GitHub and the registries, and writes only
to the work directory:

```sh
export GH_TOKEN="$(gh auth token)"
# The destination registry is private. Log in to read it.
echo "$GH_TOKEN" | docker login ghcr.io -u <user> --password-stdin
# Build the program and install kwctl, sbom-utility, cosign and gh into bin/
make build runtime-tools

# Put the pinned tools of bin/ first on the PATH for the commands below
export PATH="$PWD/bin:$PATH"

# Find the releases that need a repackaging
bin/repackager discover --repository rancher/suse-security-policies \
  --policy-name pod-privileged-policy

# Run every step for one of them, without writes
DRY_RUN=true REPOSITORY=rancher/suse-security-policies SHA="$(git rev-parse HEAD)" \
  POLICY_NAME=pod-privileged-policy POLICY_VERSION=1.0.13 \
  make repackage

# The same with the program, and keep the files of the run in work/
bin/repackager repackage --dry-run \
  --repository rancher/suse-security-policies --sha "$(git rev-parse HEAD)" \
  --policy-name pod-privileged-policy --policy-version 1.0.13 \
  --work-dir work
```

On your computer, always run these commands as a dry run. The program gets
its Sigstore identity only from GitHub Actions. Without `DRY_RUN=true` or
`--dry-run`, the program stops before the first step if `GITHUB_WORKFLOW_REF`
is not set.

## Configuration

The file [`config.yaml`](config.yaml) contains all the values that depend on
the environment:

- The upstream repository and registry.
- The expected signer identity.
- The destination registry.
- The SUSE metadata and the SBOM values.
- The list of excluded policies.

To move to a different registry, change `config.yaml` and the registry login
step. No other change is necessary.

The CI runs `make check-config` on each pull request. It fails if a
value is missing.

### Updating the pinned tools

The `Makefile` pins the version of each tool, and the sha256 of its release
asset. The workflow `sync-upstream-releases.yaml` also pins the versions of
kwctl and cosign, in the `KWCTL_VERSION` and `COSIGN_VERSION` variables of the
`repackage` job. The installer actions and the version check read these
variables. For the `Makefile`, Renovate updates each version and its checksum
in the same pull request. A `# renovate:` comment on the line above each value
tells Renovate where the tool comes from:

- The comment above a version names the GitHub repository of the tool.
  Renovate looks for a newer release there.
- The comment above a checksum also has `digestVersion=<version>`. Renovate
  finds the release asset whose sha256 is the current checksum. Then it finds
  the asset with the same name in the new release and writes its sha256. If
  the release has no checksum file, as for `sbom-utility`, Renovate downloads
  the asset and computes the sha256 itself.

The version must be the exact release tag, with the `v` prefix, because
Renovate looks up the release by its tag. Keep each `# renovate:` comment on
the line just above its value. Kubewarden uses the same method in
[kubewarden/adm-controller](https://github.com/kubewarden/adm-controller/blob/main/renovate.json).

The `kwctl` releases are on the
[adm-controller releases](https://github.com/kubewarden/adm-controller/releases)
page. `kwctl annotate` writes the version of `kwctl` into the module. Thus a
new `kwctl` version changes the `io.kubewarden.kwctl` annotation of all later
releases. That annotation is on the allowlist, so this change is expected.

A new `cosign` version can change the format of the signatures and
attestations. Review such an update with care. Renovate puts the `kwctl`
and `cosign` updates in their own pull request. cosign v3 marks
`--new-bundle-format` as deprecated. Before you accept an update, make sure
that `cosign sign --new-bundle-format=false` still works.

Renovate also updates the Go modules and the GitHub Actions. The actions are
pinned by commit SHA.

### Keeping the excluded list in sync

`excluded_policies` is a copy of `EXCLUDED_FROM_PUBLISHING` in the upstream
release workflow. Upstream builds those policies but does not publish them,
because they are demos and test fixtures. If upstream changes that list,
change `config.yaml` to match.

## kwctl requirements

The workflow needs kwctl 1.39 or later. That version of `kwctl annotate` has
two behaviors:

- It removes every existing metadata section before it writes the new section.
- Without `--metadata-path`, it adds each `--annotation KEY=VALUE` pair to the
  metadata that is already in the module.

The workflow uses the second behavior. It changes only the provenance
annotations. It never exports the rest of the metadata and never reads it
back. Then it makes sure that nothing else changed and that the result
contains the new values.

The `Makefile` and the workflow pin kwctl to `v1.39.0-rc.1`, the first
build with these behaviors. When the stable `v1.39.0` release is available,
change both pins to that release.

## Known limitations

- The tag of a release points at the commit of this repository whose
  pipeline built the release. This repository contains no policy source, so
  the tag does not identify a source state of the policy. The release notes
  name the upstream source commit.
- Before you use the workflow, enable immutable releases in the settings of
  the repository. The workflow does not enable them.
- The workflow does not run by itself. A person must start it to find and
  publish new upstream releases.
- The workflow does not report a failure in any other way than the failed
  job. Nobody is told about a failure unless they watch the workflow runs.
- If a check fails after the publication, the release stays as it is. The
  release is immutable and points at the artifact. The job fails, and you
  must fix the release by hand.
- A failed run leaves its artifact in the registry, unsigned or signed, until
  the next run reuses it. Thus a tag can be visible before its release exists.
  The run already checked the module, the upstream SBOM, the source commit
  and a draft of the SUSE SBOM before the push, so the artifact always has
  the correct content. Only a failure in step 7 or later can leave an
  artifact.
- The next run reuses the artifact only if it gets the same module. If you
  change the kwctl version between a failed run and the next run, the module
  changes, and the run stops. Then you must delete the artifact by hand.
- If GitHub loses the runner of a job, the job fails. The next run that a
  person starts reuses what the lost run left.
- If the tag of a version exists without a published release, for example
  after someone deleted the release, the discovery skips the version, and the
  run stops before the push. A repository with immutable releases cannot use
  that tag again. Thus the workflow does not publish that version. A newer
  upstream version of the policy gets its release as usual.
- The pipeline does not prove that the bytes outside the metadata section are
  the same as upstream. `kwctl annotate` writes the whole module out again,
  and the upstream module went through a different kwctl version. Two changes
  can close this gap. The first is a step that removes the metadata section
  from both modules and compares the sha256 of the results. The second is an
  annotation step that writes the section without a new emit of the module.

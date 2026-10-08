# Upstream SBOMs contain no dependency inventory

Status: open, upstream
Found: while replacing the SBOM handling with two documents per release

## What happens

`kubewarden/policies` generates its SBOM with a syft scan of the policy
directory, in `.github/workflows/release.yml`:

    syft scan --output spdx-json=policy-sbom.spdx.json \
      --source-name <title>-<version> \
      --source-version ${{ github.sha }} \
      -vv dir:.

The result contains a single package: the syft directory root. No crates, no
Go modules, no licence data.

| Release | packages | files |
|---|---|---|
| disallow-service-nodeport-policy/v1.0.8 | 1 | 0 |
| volumeMounts-policy/v1.0.12 | 1 | 43 |
| unique-service-selector-policy/v1.0.14 | 1 | 41 |

The single package looks like this in every case:

    {
      "SPDXID": "SPDXRef-DocumentRoot-Directory-disallow-service-nodeport-1.0.8",
      "versionInfo": "9249cc8dc50acd480a7395181fcaa1f0f7ac0a75",
      "supplier": "NOASSERTION",
      "downloadLocation": "NOASSERTION",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "primaryPackagePurpose": "FILE"
    }

The `versionInfo` is the upstream git commit, from `--source-version`. That is
the one genuinely useful piece of data in the document, and this repository now
carries it in the `sourceInfo` field of the SUSE SBOM.

## Why it matters here

This repository publishes two SBOMs per release: the upstream document,
byte-identical and still verifiable against the upstream Sigstore identity, and
a SUSE document describing the artifact we ship.

The SUSE document is deliberately a distribution record. It binds the published
Wasm module to its sha256 and its OCI digest, states who repackaged it and from
where, and points at the upstream document through `externalDocumentRefs` and a
`GENERATED_FROM` relationship.

Neither document answers "what is this policy built from". The SUSE one does not
claim to. The upstream one is supposed to, and does not.

Anyone expecting to scan these policies for vulnerable dependencies will find
nothing to scan. That is not a defect introduced by the repackaging; the
repackaging only makes it visible.

## Options

1. Fix it upstream. Run syft where the lockfiles are, rather than over a
   directory that has none. This is the real fix: it benefits every consumer of
   the upstream releases, not only SUSE, and it keeps the inventory attributable
   to the party that actually built the code.

2. Scan the module here. `syft scan file:suse-policy.wasm` with the
   `cargo-auditable` cataloguer can recover the crate list, but only if the
   module was built with `cargo auditable`. Needs a spike to find out. The
   TinyGo policies would need a separate answer.

   This would make the SUSE document strictly more informative than the upstream
   one, which is an odd place for a repackager to end up, and it adds a
   cataloguing step whose output drifts with the syft version.

Option 1 is preferred. Option 2 is a reasonable stopgap if upstream does not
move, and it does not conflict with the current design: extra packages and
`DEPENDS_ON` relationships can be added to the SUSE document without changing
any of the provenance fields or the pre-release checks.

## Next step

Raise it with the Kubewarden maintainers and link the issue here.

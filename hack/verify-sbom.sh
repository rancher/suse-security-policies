#!/usr/bin/env bash
#
# Check the generated SUSE SBOM against the files that are about to be
# released.
#
# Every field of the SUSE document is produced by generate-sbom.sh, and a
# generator can be wrong. Each check below pins exactly one of those fields to
# something observable, so no claim in the document reaches a consumer without
# having been confirmed against the real artifact.
#
# The checks here are deliberately offline. The signature and attestation
# checks need cosign and the registry, so they live in the workflow.
#
# Usage: verify-sbom.sh <suse.spdx.json> <upstream.spdx.json> <policy.wasm>
#
# Environment:
#   POLICY_ID           required
#   DEST_IMMUTABLE_REF  required, "<registry>/<id>@sha256:..." from kwctl push
#   SKIP_SCHEMA_CHECK   optional, set to "true" to skip the schema validation.
#                       Without it, a missing sbom-utility fails the check.

set -euo pipefail

suse_sbom="${1:?usage: verify-sbom.sh <suse.spdx.json> <upstream.spdx.json> <policy.wasm>}"
upstream_sbom="${2:?usage: verify-sbom.sh <suse.spdx.json> <upstream.spdx.json> <policy.wasm>}"
wasm="${3:?usage: verify-sbom.sh <suse.spdx.json> <upstream.spdx.json> <policy.wasm>}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${DEST_IMMUTABLE_REF:?DEST_IMMUTABLE_REF must be set}"

failed=0

fail() {
  echo "::error::$1" >&2
  failed=1
}

pass() {
  echo "  OK: $1" >&2
}

compare() {
  local description="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    pass "$description"
  else
    fail "${description}: expected '${expected}', got '${actual}'"
  fi
}

package_id="SPDXRef-Package-${POLICY_ID}"

# ---------------------------------------------------------------------------
# 1. The document is valid SPDX 2.3.
# ---------------------------------------------------------------------------
#
# Signing a malformed document is worse than not signing one: the signature
# lends authority to something no tool can read. The check is skipped only
# when SKIP_SCHEMA_CHECK asks for it. A missing sbom-utility is a failure,
# because in the release workflow it means the tool installation broke, and
# a silent skip would ship a document nobody validated.
if [[ "${SKIP_SCHEMA_CHECK:-false}" == "true" ]]; then
  echo "  SKIP: SPDX schema validation (SKIP_SCHEMA_CHECK is set)" >&2
elif ! command -v sbom-utility > /dev/null; then
  fail "sbom-utility is not installed, set SKIP_SCHEMA_CHECK=true to skip the SPDX schema validation"
elif sbom-utility validate --input-file "$suse_sbom" > /dev/null 2>&1; then
  pass "the document is valid SPDX 2.3"
else
  fail "the document is not valid SPDX 2.3"
  sbom-utility validate --input-file "$suse_sbom" >&2 || true
fi

# ---------------------------------------------------------------------------
# 2. The external document reference points at the upstream file we ship.
# ---------------------------------------------------------------------------
#
# This is the link that replaces the mutation of the upstream document. If the
# hash does not match the file attached to the release, a consumer following
# the reference ends up at a document we never looked at.
compare "the external document reference matches the attached upstream SBOM" \
  "$(sha256sum "$upstream_sbom" | cut -d' ' -f1)" \
  "$(jq -r '
    [ .externalDocumentRefs[]? | select(.externalDocumentId == "DocumentRef-upstream") ]
    | first.checksum.checksumValue // ""' "$suse_sbom")"

compare "the external document reference carries the upstream namespace" \
  "$(jq -r '.documentNamespace // ""' "$upstream_sbom")" \
  "$(jq -r '
    [ .externalDocumentRefs[]? | select(.externalDocumentId == "DocumentRef-upstream") ]
    | first.spdxDocument // ""' "$suse_sbom")"

# ---------------------------------------------------------------------------
# 3. The package checksum matches the module we ship.
# ---------------------------------------------------------------------------
#
# Catches a document generated from an earlier build step, which is the whole
# reason the checksum is in there.
compare "the package checksum matches the policy module" \
  "$(sha256sum "$wasm" | cut -d' ' -f1)" \
  "$(jq -r --arg id "$package_id" '
    [ .packages[]? | select(.SPDXID == $id) ]
    | first.checksums[]? | select(.algorithm == "SHA256") | .checksumValue' "$suse_sbom")"

compare "the package file name matches the module we ship" \
  "$(basename "$wasm")" \
  "$(jq -r --arg id "$package_id" '
    [ .packages[]? | select(.SPDXID == $id) ] | first.packageFileName // ""' "$suse_sbom")"

# ---------------------------------------------------------------------------
# 4. The purl points at the artifact that was actually pushed.
# ---------------------------------------------------------------------------
dest_repository="${DEST_IMMUTABLE_REF%@*}"
dest_digest="${DEST_IMMUTABLE_REF#*@}"
dest_registry="${dest_repository%/*}"

compare "the purl points at the pushed artifact" \
  "pkg:oci/${POLICY_ID}@${dest_digest}?repository_url=${dest_registry}" \
  "$(jq -r --arg id "$package_id" '
    [ .packages[]? | select(.SPDXID == $id) ]
    | first.externalRefs[]? | select(.referenceType == "purl") | .referenceLocator' "$suse_sbom")"

# ---------------------------------------------------------------------------
# 5. The GENERATED_FROM relationship resolves inside the upstream document.
# ---------------------------------------------------------------------------
#
# A dangling reference would leave the SUSE document claiming a provenance that
# cannot be followed, which is the failure the two document split exists to
# avoid.
generated_from=$(jq -r --arg id "$package_id" '
  [ .relationships[]?
    | select(.relationshipType == "GENERATED_FROM")
    | select(.spdxElementId == $id)
    | .relatedSpdxElement ]
  | first // ""' "$suse_sbom")

if [[ "$generated_from" != DocumentRef-upstream:* ]]; then
  fail "the GENERATED_FROM relationship does not reference the upstream document: '${generated_from}'"
else
  upstream_element="${generated_from#DocumentRef-upstream:}"
  if [[ "$(jq -r --arg id "$upstream_element" \
      '[ .packages[]? | select(.SPDXID == $id) ] | length' "$upstream_sbom")" == "0" ]]; then
    fail "the GENERATED_FROM relationship points at '${upstream_element}', which the upstream SBOM does not contain"
  else
    pass "the GENERATED_FROM relationship resolves to ${upstream_element}"
  fi
fi

# ---------------------------------------------------------------------------
# 6. The document describes exactly the package we checked above.
# ---------------------------------------------------------------------------
#
# Without this, every check above could pass against a package the document
# does not actually describe.
compare "the document describes the policy package" \
  "$package_id" \
  "$(jq -r '
    [ .relationships[]?
      | select(.relationshipType == "DESCRIBES")
      | select(.spdxElementId == "SPDXRef-DOCUMENT")
      | .relatedSpdxElement ]
    | first // ""' "$suse_sbom")"

compare "the document describes a single package" \
  "1" \
  "$(jq -r '.packages | length' "$suse_sbom")"

if [[ "$failed" -ne 0 ]]; then
  echo "::error::The generated SBOM does not match the artifacts being released" >&2
  exit 1
fi

echo "The generated SBOM matches the artifacts being released" >&2

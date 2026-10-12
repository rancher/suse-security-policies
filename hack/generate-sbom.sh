#!/usr/bin/env bash
#
# Generate the SUSE SPDX document for a repackaged policy.
#
# Every release carries two SBOMs. The upstream document is republished
# byte-identical, so it keeps verifying against the upstream Sigstore identity
# and stays the authoritative record of what upstream scanned. This script
# produces the second one: a distribution record that describes the artifact
# SUSE actually ships.
#
# Nothing from the upstream document is copied into the new one except the
# facts we are entitled to repeat: its namespace and hash, the SPDXID of the
# package it describes, the upstream source commit and the licence fields
# upstream concluded. Everything else is generated here, which is why every
# field has a matching assertion in verify-sbom.sh.
#
# The caller must have verified the upstream signature before invoking this
# script, and must have pushed the module already, because the document records
# the manifest digest of the published artifact.
#
# Usage: generate-sbom.sh <upstream.spdx.json> <output.spdx.json>
#
# Environment:
#   CONFIG_FILE         optional, defaults to config.yaml
#   POLICY_ID           required, last segment of the ociUrl annotation
#   POLICY_VERSION      required, without the "v" prefix
#   UPSTREAM_TAG        required
#   UPSTREAM_REPOSITORY required, "owner/repo"
#   UPSTREAM_DIGEST     required, "sha256:..." of the upstream OCI manifest
#   WASM_FILE           required, path to the module attached to the release
#   WASM_ASSET_NAME     required, name of that module as a release asset
#   DEST_IMMUTABLE_REF  required, "<registry>/<id>@sha256:..." from kwctl push
#   GITHUB_REPOSITORY   required, "owner/repo" of this repository
#   GITHUB_SHA          required, commit that generated the document

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

upstream_sbom="${1:?usage: generate-sbom.sh <upstream.spdx.json> <output.spdx.json>}"
output="${2:?usage: generate-sbom.sh <upstream.spdx.json> <output.spdx.json>}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${POLICY_VERSION:?POLICY_VERSION must be set}"
: "${UPSTREAM_TAG:?UPSTREAM_TAG must be set}"
: "${UPSTREAM_REPOSITORY:?UPSTREAM_REPOSITORY must be set}"
: "${UPSTREAM_DIGEST:?UPSTREAM_DIGEST must be set}"
: "${WASM_FILE:?WASM_FILE must be set}"
: "${WASM_ASSET_NAME:?WASM_ASSET_NAME must be set}"
: "${DEST_IMMUTABLE_REF:?DEST_IMMUTABLE_REF must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_SHA:?GITHUB_SHA must be set}"

if [[ ! -s "$WASM_FILE" ]]; then
  echo "::error::${WASM_FILE} is missing or empty" >&2
  exit 1
fi

NAMESPACE_BASE=$(yq -r '.sbom.namespace_base' "$CONFIG_FILE")
SUPPLIER=$(yq -r '.sbom.supplier' "$CONFIG_FILE")
ORIGINATOR=$(yq -r '.sbom.originator' "$CONFIG_FILE")
TOOL_NAME=$(yq -r '.sbom.tool_name' "$CONFIG_FILE")

# ---------------------------------------------------------------------------
# Resolve the package the upstream document describes.
# ---------------------------------------------------------------------------
#
# Both the modern relationship form and the legacy documentDescribes field are
# accepted, because the exact shape depends on the tool that produced the SBOM.
# The GENERATED_FROM relationship has to point at exactly one element, so
# anything else is a hard failure: guessing a root would make the new document
# claim a provenance nobody checked.
mapfile -t described < <(
  jq -r '
    ( [ (.relationships // [])[]
        | select(.relationshipType == "DESCRIBES")
        | select(.spdxElementId == "SPDXRef-DOCUMENT")
        | .relatedSpdxElement ]
      + (.documentDescribes // [])
      | unique
    )[]' "$upstream_sbom"
)

if [[ "${#described[@]}" -ne 1 ]]; then
  echo "::error::The upstream SBOM describes ${#described[@]} packages, expected exactly 1: ${described[*]:-none}" >&2
  exit 1
fi

upstream_root_id="${described[0]}"

upstream_namespace=$(jq -r '.documentNamespace // ""' "$upstream_sbom")
if [[ -z "$upstream_namespace" ]]; then
  echo "::error::The upstream SBOM has no documentNamespace, it cannot be referenced" >&2
  exit 1
fi

# The upstream root package carries the git commit the policy was built from in
# versionInfo, because the upstream release workflow passes "--source-version
# ${{ github.sha }}" to syft. That is the most precise provenance upstream
# publishes, so it is worth carrying over.
upstream_root=$(jq --arg id "$upstream_root_id" \
  '[.packages[]? | select(.SPDXID == $id)] | first // {}' "$upstream_sbom")

upstream_commit=$(jq -r '.versionInfo // "unknown"' <<<"$upstream_root")

# Licences are copied, never asserted. We did not determine them, so we repeat
# what upstream concluded, which today is NOASSERTION everywhere. If upstream
# ever populates these fields, the repackaged document follows automatically.
license_concluded=$(jq -r '.licenseConcluded // "NOASSERTION"' <<<"$upstream_root")
license_declared=$(jq -r '.licenseDeclared // "NOASSERTION"' <<<"$upstream_root")
copyright_text=$(jq -r '.copyrightText // "NOASSERTION"' <<<"$upstream_root")

# ---------------------------------------------------------------------------
# Facts about our own artifact.
# ---------------------------------------------------------------------------

upstream_sha256=$(sha256sum "$upstream_sbom" | cut -d' ' -f1)
wasm_sha256=$(sha256sum "$WASM_FILE" | cut -d' ' -f1)

# "<registry>/<id>@sha256:<digest>" is split into the two halves a purl needs.
dest_repository="${DEST_IMMUTABLE_REF%@*}"
dest_digest="${DEST_IMMUTABLE_REF#*@}"
dest_registry="${dest_repository%/*}"

if [[ "$dest_digest" != sha256:* ]]; then
  echo "::error::DEST_IMMUTABLE_REF must contain a sha256 digest, got '${DEST_IMMUTABLE_REF}'" >&2
  exit 1
fi

# An SPDX documentNamespace must be unique per document. The spec recommends a
# UUID, and "created" below already makes the document non-reproducible, so
# there is nothing to gain from deriving it from the content.
uuid=$(cat /proc/sys/kernel/random/uuid)
namespace="${NAMESPACE_BASE}/${POLICY_ID}/${POLICY_VERSION}-${uuid}"

# The asset URL is a function of the repository, the tag and the file name, so
# it is known before the release exists. The workflow confirms it resolves once
# the release has been created.
download_location="https://github.com/${GITHUB_REPOSITORY}/releases/download/${UPSTREAM_TAG}/${WASM_ASSET_NAME}"

purl="pkg:oci/${POLICY_ID}@${dest_digest}?repository_url=${dest_registry}"

# The module is not rebuilt, but it is not untouched either: the repackaging
# replaces the Kubewarden metadata section. Saying "unmodified" without that
# qualifier would contradict what the pipeline does.
source_info="Repackaged by SUSE from https://github.com/${UPSTREAM_REPOSITORY} release ${UPSTREAM_TAG} (upstream OCI digest ${UPSTREAM_DIGEST}, upstream source commit ${upstream_commit}). The WebAssembly code sections are unmodified; the io.kubewarden.metadata custom section was replaced with SUSE provenance annotations."

# ---------------------------------------------------------------------------
# Emit the document.
# ---------------------------------------------------------------------------

jq -n \
  --arg name "${POLICY_ID}-${POLICY_VERSION}" \
  --arg namespace "$namespace" \
  --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg supplier "$SUPPLIER" \
  --arg originator "$ORIGINATOR" \
  --arg tool "Tool: ${TOOL_NAME}-${GITHUB_SHA}" \
  --arg upstreamNamespace "$upstream_namespace" \
  --arg upstreamSha256 "$upstream_sha256" \
  --arg upstreamRootId "$upstream_root_id" \
  --arg policyId "$POLICY_ID" \
  --arg version "$POLICY_VERSION" \
  --arg wasmAssetName "$WASM_ASSET_NAME" \
  --arg wasmSha256 "$wasm_sha256" \
  --arg downloadLocation "$download_location" \
  --arg purl "$purl" \
  --arg sourceInfo "$source_info" \
  --arg licenseConcluded "$license_concluded" \
  --arg licenseDeclared "$license_declared" \
  --arg copyrightText "$copyright_text" \
  '
  ("SPDXRef-Package-" + $policyId) as $packageId
  |
  {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: $name,
    documentNamespace: $namespace,
    creationInfo: {
      created: $created,
      creators: ["Organization: SUSE", $tool]
    },
    externalDocumentRefs: [
      {
        externalDocumentId: "DocumentRef-upstream",
        spdxDocument: $upstreamNamespace,
        checksum: {
          algorithm: "SHA256",
          checksumValue: $upstreamSha256
        }
      }
    ],
    packages: [
      {
        SPDXID: $packageId,
        name: $policyId,
        versionInfo: $version,
        packageFileName: $wasmAssetName,
        checksums: [
          {
            algorithm: "SHA256",
            checksumValue: $wasmSha256
          }
        ],
        filesAnalyzed: false,
        primaryPackagePurpose: "APPLICATION",
        supplier: $supplier,
        originator: $originator,
        downloadLocation: $downloadLocation,
        externalRefs: [
          {
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: $purl
          }
        ],
        sourceInfo: $sourceInfo,
        licenseConcluded: $licenseConcluded,
        licenseDeclared: $licenseDeclared,
        copyrightText: $copyrightText
      }
    ],
    relationships: [
      {
        spdxElementId: "SPDXRef-DOCUMENT",
        relatedSpdxElement: $packageId,
        relationshipType: "DESCRIBES"
      },
      {
        spdxElementId: $packageId,
        relatedSpdxElement: ("DocumentRef-upstream:" + $upstreamRootId),
        relationshipType: "GENERATED_FROM"
      }
    ]
  }
  ' > "$output"

echo "SUSE SBOM written to ${output}" >&2
echo "  describes ${WASM_ASSET_NAME} sha256 ${wasm_sha256}" >&2
echo "  derived from the upstream SBOM sha256 ${upstream_sha256}" >&2

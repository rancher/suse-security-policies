#!/usr/bin/env bash
#
# Adapt an upstream SPDX SBOM to the SUSE repackage.
#
# The caller must have verified the upstream signature before invoking this
# script. Only document level provenance is rewritten. Package entries,
# SPDXIDs and relationships are left untouched, because they describe the real
# dependency set and rewriting them would make the document lie.
#
# Patching the content necessarily invalidates the upstream signature, so the
# sha256 of the original document is recorded inside the new one. That keeps
# the chain auditable: anyone can fetch the upstream SBOM, hash it and confirm
# it is the document this one was derived from.
#
# Usage: adapt-sbom.sh <input.spdx.json> <output.spdx.json>
#
# Environment:
#   CONFIG_FILE      optional, defaults to config.yaml
#   POLICY_ID        required
#   POLICY_VERSION   required
#   UPSTREAM_TAG     required
#   UPSTREAM_REPOSITORY_URL required

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

input="${1:?usage: adapt-sbom.sh <input.spdx.json> <output.spdx.json>}"
output="${2:?usage: adapt-sbom.sh <input.spdx.json> <output.spdx.json>}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${POLICY_VERSION:?POLICY_VERSION must be set}"
: "${UPSTREAM_TAG:?UPSTREAM_TAG must be set}"
: "${UPSTREAM_REPOSITORY_URL:?UPSTREAM_REPOSITORY_URL must be set}"

ORGANIZATION=$(yq -r '.sbom.organization' "$CONFIG_FILE")
NAMESPACE_BASE=$(yq -r '.sbom.namespace_base' "$CONFIG_FILE")
SUPPLIER=$(yq -r '.sbom.supplier' "$CONFIG_FILE")
DOWNLOAD_LOCATION=$(yq -r '.sbom.download_location' "$CONFIG_FILE")

upstream_sha256=$(sha256sum "$input" | cut -d' ' -f1)

# An SPDX documentNamespace must be unique per document. Deriving it from the
# policy, version and the hash of the source document keeps it unique while
# staying reproducible across re-runs.
namespace="${NAMESPACE_BASE}/${POLICY_ID}/${POLICY_VERSION}-${upstream_sha256:0:12}"
document_name="${POLICY_ID}-${POLICY_VERSION}"

jq \
  --arg name "$document_name" \
  --arg namespace "$namespace" \
  --arg organization "Organization: ${ORGANIZATION}" \
  --arg supplier "$SUPPLIER" \
  --arg downloadLocation "$DOWNLOAD_LOCATION" \
  --arg upstreamSha256 "$upstream_sha256" \
  --arg upstreamTag "$UPSTREAM_TAG" \
  --arg upstreamRepositoryUrl "$UPSTREAM_REPOSITORY_URL" \
  '
  # Identify the packages the document describes. Both the modern relationship
  # form and the legacy documentDescribes field are accepted, since the exact
  # shape depends on the tool and version that produced the SBOM.
  ( [ (.relationships // [])[]
      | select(.relationshipType == "DESCRIBES")
      | select(.spdxElementId == "SPDXRef-DOCUMENT")
      | .relatedSpdxElement ]
    + (.documentDescribes // [])
    | unique
  ) as $described
  |
  .name = $name
  | .documentNamespace = $namespace
  | .creationInfo.creators = (
      ((.creationInfo.creators // []) + [$organization]) | unique
    )
  | .comment = (
      "Repackaged by SUSE from " + $upstreamRepositoryUrl + " release " + $upstreamTag
      + ". Derived from the upstream SBOM with sha256 " + $upstreamSha256
      + ", which is signed by the upstream release pipeline."
    )
  | .packages = [
      (.packages // [])[]
      | if (.SPDXID as $id | $described | index($id))
        then .supplier = $supplier | .downloadLocation = $downloadLocation
        else .
        end
    ]
  ' "$input" > "$output"

echo "Adapted SBOM written to ${output} (upstream sha256 ${upstream_sha256})" >&2

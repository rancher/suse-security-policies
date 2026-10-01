#!/usr/bin/env bash
#
# Check that the repackaged policy carries the new metadata.
#
# The diff guard compares the metadata before and after the repackaging. It
# cannot see a module that kept the upstream metadata section, because both
# files then hold the same values. This check reads the metadata of the
# repackaged module and requires the values that only the repackaging can
# produce.
#
# Usage: check-repackaged-metadata.sh <repackaged-metadata.yaml>
#
# Environment:
#   CONFIG_FILE       optional, defaults to config.yaml
#   POLICY_ID         required
#   UPSTREAM_DIGEST   required

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

metadata="${1:?usage: check-repackaged-metadata.sh <repackaged-metadata.yaml>}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${UPSTREAM_DIGEST:?UPSTREAM_DIGEST must be set}"

DEST_REGISTRY=$(yq -r '.destination.registry' "$CONFIG_FILE")

failed=0

expected_oci_url="${DEST_REGISTRY}/${POLICY_ID}"
actual_oci_url=$(yq -r '.annotations."io.kubewarden.policy.ociUrl" // ""' "$metadata")

if [[ "$actual_oci_url" != "$expected_oci_url" ]]; then
  echo "::error::The repackaged policy points at '${actual_oci_url}' instead of '${expected_oci_url}'" >&2
  failed=1
fi

actual_digest=$(yq -r '.annotations."com.suse.policy.upstream.digest" // ""' "$metadata")

if [[ "$actual_digest" != "$UPSTREAM_DIGEST" ]]; then
  echo "::error::The repackaged policy records the upstream digest '${actual_digest}' instead of '${UPSTREAM_DIGEST}'" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "::error::The repackaged policy does not carry the expected metadata. The module probably kept the metadata section of the upstream module." >&2
  exit 1
fi

echo "The repackaged policy carries the expected metadata" >&2

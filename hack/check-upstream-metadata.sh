#!/usr/bin/env bash
#
# Check that the verified upstream module is the release we asked for.
#
# The discovery reads the policy id and the version from metadata.yml in the
# upstream git repository. The signature check pins the signer to the release
# tag. Neither of them reads the metadata of the module itself. This check
# compares the metadata inside the verified module with the policy id and the
# version of the run, so that git and the module must agree.
#
# The title is not checked. Upstream titles can differ from the directory
# names, for example "affinity-node-selector" in the directory
# "ControllerAffinityNodeSelector".
#
# Usage: check-upstream-metadata.sh <upstream-metadata.yaml>
#
# Environment:
#   CONFIG_FILE       optional, defaults to config.yaml
#   POLICY_ID         required
#   POLICY_VERSION    required, without the "v" prefix

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

metadata="${1:?usage: check-upstream-metadata.sh <upstream-metadata.yaml>}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${POLICY_VERSION:?POLICY_VERSION must be set}"

UPSTREAM_REGISTRY=$(yq -r '.upstream.registry' "$CONFIG_FILE")

failed=0

actual_version=$(yq -r '.annotations."io.kubewarden.policy.version" // ""' "$metadata")

if [[ "$actual_version" != "$POLICY_VERSION" ]]; then
  echo "::error::The upstream module has the version '${actual_version}', but the release is '${POLICY_VERSION}'" >&2
  failed=1
fi

expected_oci_url="${UPSTREAM_REGISTRY}/${POLICY_ID}"
actual_oci_url=$(yq -r '.annotations."io.kubewarden.policy.ociUrl" // ""' "$metadata")

if [[ "$actual_oci_url" != "$expected_oci_url" ]]; then
  echo "::error::The upstream module points at '${actual_oci_url}' instead of '${expected_oci_url}'" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "::error::The verified upstream module is not the release this run repackages" >&2
  exit 1
fi

echo "The upstream module matches the release" >&2

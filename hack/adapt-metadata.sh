#!/usr/bin/env bash
#
# Adapt the metadata extracted from an upstream policy to SUSE.
#
# Reads the YAML produced by "kwctl inspect -o yaml --no-signatures" and writes
# a metadata file suitable for "kwctl annotate -m". Only provenance annotations
# are rewritten. The behavioural fields (rules, mutating, contextAware,
# executionMode) and the policy version are left untouched so the repackaged
# module stays functionally identical to the upstream one.
#
# Usage: adapt-metadata.sh <input.yaml> <output.yaml>
#
# Environment:
#   CONFIG_FILE       optional, defaults to config.yaml
#   POLICY_ID         required
#   UPSTREAM_TAG      required
#   UPSTREAM_DIGEST   required
#   UPSTREAM_RELEASE_URL required

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

input="${1:?usage: adapt-metadata.sh <input.yaml> <output.yaml>}"
output="${2:?usage: adapt-metadata.sh <input.yaml> <output.yaml>}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${UPSTREAM_TAG:?UPSTREAM_TAG must be set}"
: "${UPSTREAM_DIGEST:?UPSTREAM_DIGEST must be set}"
: "${UPSTREAM_RELEASE_URL:?UPSTREAM_RELEASE_URL must be set}"

DEST_REGISTRY=$(yq -r '.destination.registry' "$CONFIG_FILE")
UPSTREAM_REPOSITORY=$(yq -r '.upstream.repository' "$CONFIG_FILE")
AUTHOR=$(yq -r '.metadata.author' "$CONFIG_FILE")
URL=$(yq -r '.metadata.url' "$CONFIG_FILE")
SOURCE=$(yq -r '.metadata.source' "$CONFIG_FILE")

OCI_URL="${DEST_REGISTRY}/${POLICY_ID}"

# yq (mikefarah) has no --arg, values are passed through the environment and
# read back with strenv() so that no value is ever interpolated into the
# expression itself.
export SUSE_OCI_URL="$OCI_URL"
export SUSE_AUTHOR="$AUTHOR"
export SUSE_URL="$URL"
export SUSE_SOURCE="$SOURCE"
export SUSE_UPSTREAM_REPOSITORY="$UPSTREAM_REPOSITORY"
export SUSE_UPSTREAM_TAG="$UPSTREAM_TAG"
export SUSE_UPSTREAM_DIGEST="$UPSTREAM_DIGEST"
export SUSE_UPSTREAM_RELEASE_URL="$UPSTREAM_RELEASE_URL"

yq '
  .annotations."io.kubewarden.policy.ociUrl" = strenv(SUSE_OCI_URL) |
  .annotations."io.kubewarden.policy.author" = strenv(SUSE_AUTHOR) |
  .annotations."io.kubewarden.policy.url" = strenv(SUSE_URL) |
  .annotations."io.kubewarden.policy.source" = strenv(SUSE_SOURCE) |
  .annotations."com.suse.policy.upstream.repository" = strenv(SUSE_UPSTREAM_REPOSITORY) |
  .annotations."com.suse.policy.upstream.tag" = strenv(SUSE_UPSTREAM_TAG) |
  .annotations."com.suse.policy.upstream.digest" = strenv(SUSE_UPSTREAM_DIGEST) |
  .annotations."com.suse.policy.upstream.release-url" = strenv(SUSE_UPSTREAM_RELEASE_URL)
  ' "$input" > "$output"

echo "Adapted metadata written to ${output}" >&2

#!/usr/bin/env bash
#
# Print the annotations that change an upstream policy into a SUSE policy.
#
# The script prints one KEY=VALUE pair on each line. The workflow gives each
# pair to "kwctl annotate --annotation". If you do not give --metadata-path,
# kwctl changes only these keys in the metadata of the module. kwctl does not
# change the other fields. Thus the behavior fields (rules, mutating,
# contextAware, executionMode) and the policy version stay as upstream wrote
# them.
#
# The list contains only provenance annotations. Provenance annotations tell
# who publishes the policy and where it comes from. Other keys do not pass
# the allowlist in check-metadata-diff.sh.
#
# "io.kubewarden.policy.source" is not in the list. It tells where the source
# code of the policy is. This repository holds no source code, so the
# annotation keeps the upstream value.
#
# "io.kubewarden.policy.author" names SUSE, the publisher of the repackaged
# policy. The upstream author goes into "com.suse.policy.upstream.author", so
# the information stays in the module. The script reads it from the metadata
# of the upstream module.
#
# Usage: annotation-args.sh
#
# Environment:
#   CONFIG_FILE          optional, defaults to config.yaml
#   POLICY_ID            required
#   UPSTREAM_TAG         required
#   UPSTREAM_DIGEST      required
#   UPSTREAM_RELEASE_URL required
#   UPSTREAM_METADATA    required, "kwctl inspect -o yaml" output of the
#                        upstream module

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

: "${POLICY_ID:?POLICY_ID must be set}"
: "${UPSTREAM_TAG:?UPSTREAM_TAG must be set}"
: "${UPSTREAM_DIGEST:?UPSTREAM_DIGEST must be set}"
: "${UPSTREAM_RELEASE_URL:?UPSTREAM_RELEASE_URL must be set}"
: "${UPSTREAM_METADATA:?UPSTREAM_METADATA must be set}"

DEST_REGISTRY=$(yq -r '.destination.registry' "$CONFIG_FILE")
UPSTREAM_REPOSITORY=$(yq -r '.upstream.repository' "$CONFIG_FILE")
AUTHOR=$(yq -r '.metadata.author' "$CONFIG_FILE")
URL=$(yq -r '.metadata.url' "$CONFIG_FILE")
UPSTREAM_AUTHOR=$(yq -r '.annotations."io.kubewarden.policy.author" // ""' "$UPSTREAM_METADATA")

annotations=(
  "io.kubewarden.policy.ociUrl=${DEST_REGISTRY}/${POLICY_ID}"
  "io.kubewarden.policy.author=${AUTHOR}"
  "io.kubewarden.policy.url=${URL}"
  "com.suse.policy.upstream.repository=${UPSTREAM_REPOSITORY}"
  "com.suse.policy.upstream.tag=${UPSTREAM_TAG}"
  "com.suse.policy.upstream.digest=${UPSTREAM_DIGEST}"
  "com.suse.policy.upstream.release-url=${UPSTREAM_RELEASE_URL}"
  "com.suse.policy.upstream.author=${UPSTREAM_AUTHOR}"
)

for annotation in "${annotations[@]}"; do
  key="${annotation%%=*}"
  value="${annotation#*=}"

  # kwctl reads KEY=@PATH as "read the value from the file at PATH". Thus a
  # value that starts with "@" becomes a file read. A newline in a value
  # puts one pair on two lines.
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "::error::The value of ${key} is empty" >&2
    exit 1
  fi
  if [[ "$value" == @* ]]; then
    echo "::error::The value of ${key} starts with '@', which kwctl would read as a file path: ${value}" >&2
    exit 1
  fi
  if [[ "$value" == *$'\n'* ]]; then
    echo "::error::The value of ${key} contains a newline" >&2
    exit 1
  fi

  printf '%s\n' "$annotation"
done

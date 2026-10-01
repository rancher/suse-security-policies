#!/usr/bin/env bash
#
# Guard against unintended metadata changes.
#
# Compares the metadata extracted from the upstream module with the metadata
# extracted from the repackaged module and fails if anything outside the
# allowlist differs. This is what keeps the repackaging honest: the module must
# stay functionally identical to the one upstream signed, and only provenance
# annotations may move.
#
# Usage: check-metadata-diff.sh <upstream.yaml> <repackaged.yaml>

set -euo pipefail

upstream="${1:?usage: check-metadata-diff.sh <upstream.yaml> <repackaged.yaml>}"
repackaged="${2:?usage: check-metadata-diff.sh <upstream.yaml> <repackaged.yaml>}"

# Annotations we deliberately rewrite, plus the kwctl version stamp that
# "kwctl annotate" always refreshes with the version of the tool that ran.
ALLOWED_ANNOTATIONS=(
  "io.kubewarden.policy.ociUrl"
  "io.kubewarden.policy.author"
  "io.kubewarden.policy.url"
  "io.kubewarden.policy.source"
  "io.kubewarden.policy.kwctl-version"
  "com.suse.policy.upstream.repository"
  "com.suse.policy.upstream.tag"
  "com.suse.policy.upstream.digest"
  "com.suse.policy.upstream.release-url"
)

failed=0

# Everything except the annotations map must be byte-for-byte identical. This
# covers rules, mutating, contextAware, executionMode, protocolVersion and
# minimumKubewardenVersion in one comparison, so a newly introduced field is
# caught too instead of being silently ignored.
if ! diff -u \
  <(yq 'del(.annotations)' "$upstream") \
  <(yq 'del(.annotations)' "$repackaged"); then
  echo "::error::The repackaged policy changed fields outside of .annotations" >&2
  failed=1
fi

# The set of annotation keys must not change: adding or dropping a key that is
# not in the allowlist would alter how the policy is presented.
allowed_json=$(printf '%s\n' "${ALLOWED_ANNOTATIONS[@]}" | jq -R . | jq -sc .)

changed=$(
  jq -n \
    --slurpfile a <(yq -o=json '.annotations // {}' "$upstream") \
    --slurpfile b <(yq -o=json '.annotations // {}' "$repackaged") \
    --argjson allowed "$allowed_json" '
      ($a[0]) as $up | ($b[0]) as $new |
      (($up | keys) + ($new | keys) | unique) as $keys |
      [ $keys[]
        | select(($up[.] // null) != ($new[.] // null))
        | select(. as $k | $allowed | index($k) | not)
      ]'
)

if [[ "$(jq 'length' <<<"$changed")" -ne 0 ]]; then
  echo "::error::The repackaged policy changed annotations outside of the allowlist:" >&2
  jq -r '.[] | "  - " + .' <<<"$changed" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "Metadata diff is limited to the allowlisted provenance annotations" >&2

#!/usr/bin/env bash
#
# Render the release notes for a repackaged policy.
#
# The upstream changelog is reused verbatim except for references that would
# resolve against the wrong repository once rendered here:
#
#   * "(#123)" becomes "(kubewarden/policies#123)". A bare "#123" links to the
#     issue or pull request of the repository the text is rendered in, so
#     copying it unchanged would point at an unrelated item in this repository.
#   * "@user" is wrapped in backticks so that republishing the changelog does
#     not notify people from a repository they do not follow.
#
# Usage: render-changelog.sh <upstream-body-file>   (writes to stdout)
#
# Environment:
#   CONFIG_FILE           optional, defaults to config.yaml
#   POLICY_NAME           required
#   POLICY_ID             required
#   POLICY_VERSION        required
#   UPSTREAM_TAG          required
#   UPSTREAM_RELEASE_URL  required
#   UPSTREAM_DIGEST       required
#   DEST_OCI_REF          required

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"

body_file="${1:?usage: render-changelog.sh <upstream-body-file>}"

: "${POLICY_NAME:?POLICY_NAME must be set}"
: "${POLICY_ID:?POLICY_ID must be set}"
: "${POLICY_VERSION:?POLICY_VERSION must be set}"
: "${UPSTREAM_TAG:?UPSTREAM_TAG must be set}"
: "${UPSTREAM_RELEASE_URL:?UPSTREAM_RELEASE_URL must be set}"
: "${UPSTREAM_DIGEST:?UPSTREAM_DIGEST must be set}"
: "${DEST_OCI_REF:?DEST_OCI_REF must be set}"

UPSTREAM_REPOSITORY=$(yq -r '.upstream.repository' "$CONFIG_FILE")
UPSTREAM_REGISTRY=$(yq -r '.upstream.registry' "$CONFIG_FILE")

# Qualify bare issue references with the upstream repository. A negative
# lookbehind is not available in sed, so already qualified references such as
# "owner/repo#12" are protected by requiring a non-word character before "#".
#
# The two expressions use different delimiters on purpose: the mention pattern
# contains "@", so it cannot use "@" as its delimiter.
# shellcheck disable=SC2016 # backticks inside the expression are literal
changelog=$(
  sed -E \
    -e "s@(^|[^[:alnum:]_/.-])#([0-9]+)@\1${UPSTREAM_REPOSITORY}#\2@g" \
    -e 's%(^|[^[:alnum:]_`/])@([A-Za-z0-9][A-Za-z0-9-]*)%\1`@\2`%g' \
    "$body_file"
)

cat <<EOF
This is a SUSE repackage of the upstream Kubewarden policy
\`${POLICY_NAME}\` ${POLICY_VERSION}.

The WebAssembly module comes from the upstream release pipeline. Its signature
was verified and it was pulled by digest, after which only the provenance
metadata was rewritten and the artifact was signed again with this
repository's identity.

| | |
|---|---|
| Upstream release | [${UPSTREAM_TAG}](${UPSTREAM_RELEASE_URL}) |
| Verified source | \`${UPSTREAM_REGISTRY}/${POLICY_ID}@${UPSTREAM_DIGEST}\` |
| Published artifact | \`${DEST_OCI_REF}\` |

## Changelog

${changelog}
EOF

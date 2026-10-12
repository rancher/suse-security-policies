#!/usr/bin/env bash
#
# Discover which upstream policy releases still need to be repackaged.
#
# Emits a compact JSON array on stdout. Each entry describes one policy version
# that has an upstream release but no corresponding release in this repository:
#
#   [{"policy_name":"...","policy_id":"...","version":"...","tag":"...",
#     "upstream_release_url":"..."}]
#
# Environment:
#   GH_TOKEN                 required, used by the gh CLI
#   DEST_REPOSITORY          required, "owner/repo" of this repository
#   CONFIG_FILE              optional, defaults to config.yaml
#   FILTER_POLICY_NAME       optional, restrict discovery to a single policy
#   FILTER_POLICY_VERSION    optional, pin the version (requires FILTER_POLICY_NAME)
#   FORCE                    optional, "true" to ignore the dedup check
#                            (requires FILTER_POLICY_NAME)

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config.yaml}"
FILTER_POLICY_NAME="${FILTER_POLICY_NAME:-}"
FILTER_POLICY_VERSION="${FILTER_POLICY_VERSION:-}"
FORCE="${FORCE:-false}"

: "${DEST_REPOSITORY:?DEST_REPOSITORY must be set}"

log() { echo "$*" >&2; }

if [[ -n "$FILTER_POLICY_VERSION" && -z "$FILTER_POLICY_NAME" ]]; then
  log "::error::FILTER_POLICY_VERSION requires FILTER_POLICY_NAME"
  exit 1
fi

# Every queued release is republished, and a republish deletes the existing
# release and overwrites the OCI tag. Without a policy name, force would do
# that to every policy at once.
if [[ "$FORCE" == "true" && -z "$FILTER_POLICY_NAME" ]]; then
  log "::error::FORCE requires FILTER_POLICY_NAME"
  exit 1
fi

UPSTREAM_REPOSITORY=$(yq -r '.upstream.repository' "$CONFIG_FILE")
mapfile -t EXCLUDED < <(yq -r '.excluded_policies[]' "$CONFIG_FILE")

is_excluded() {
  local candidate="$1" excluded
  for excluded in "${EXCLUDED[@]}"; do
    [[ "$candidate" == "$excluded" ]] && return 0
  done
  return 1
}

# A release tag is "<policy-name>/v<version>". Anything that does not match
# that shape is not a policy release and is ignored.
#
# Prereleases are out of scope, so versions carrying an -alpha/-beta/-rc
# suffix are dropped here in addition to the API's own prerelease flag: a
# release can be marked stable and still carry a prerelease version string.
log "Listing releases of ${UPSTREAM_REPOSITORY}"
releases=$(gh api "repos/${UPSTREAM_REPOSITORY}/releases" --paginate --slurp |
  jq -c '
    [ .[][]
      | select(.draft == false)
      | select(.prerelease == false)
      | select(.tag_name | test("^[^/]+/v[0-9]+\\.[0-9]+\\.[0-9]+"))
      | {
          tag: .tag_name,
          policy_name: (.tag_name | split("/")[0]),
          version: (.tag_name | split("/")[1] | ltrimstr("v")),
          upstream_release_url: .html_url
        }
      | select(.version | test("-(alpha|beta|rc)") | not)
    ]')

log "Found $(jq 'length' <<<"$releases") candidate upstream releases"

# The release in this repository is created as the very last step of the
# repackaging job, so its presence means the whole pipeline succeeded.
#
# The list is fetched once, and a failure stops the discovery. A check per tag
# cannot tell "no release" from an API error, and a wrong "no release" queues a
# republish that deletes the existing release and overwrites the OCI tag.
released='[]'
if [[ "$FORCE" != "true" ]]; then
  log "Listing releases of ${DEST_REPOSITORY}"
  if ! dest_releases=$(gh api "repos/${DEST_REPOSITORY}/releases" --paginate --slurp); then
    log "::error::Cannot list the releases of ${DEST_REPOSITORY}"
    exit 1
  fi
  released=$(jq -c '[ .[][].tag_name ]' <<<"$dest_releases")
  log "Found $(jq 'length' <<<"$released") releases in ${DEST_REPOSITORY}"
fi

# Keep only the highest version of each policy. sort_by on the numeric triple
# gives a correct semver ordering; the regex above already guarantees all three
# components are present.
latest=$(jq -c '
  group_by(.policy_name)
  | map(
      sort_by(.version | split(".") | map(tonumber? // 0))
      | last
    )
  | sort_by(.policy_name)' <<<"$releases")

if [[ -n "$FILTER_POLICY_NAME" ]]; then
  if [[ -n "$FILTER_POLICY_VERSION" ]]; then
    # An explicitly requested version may be older than the latest one, so it
    # is looked up in the full release list rather than the per-policy latest.
    latest=$(jq -c --arg name "$FILTER_POLICY_NAME" --arg version "$FILTER_POLICY_VERSION" \
      'map(select(.policy_name == $name and .version == $version))' <<<"$releases")
  else
    latest=$(jq -c --arg name "$FILTER_POLICY_NAME" \
      'map(select(.policy_name == $name))' <<<"$latest")
  fi

  if [[ "$(jq 'length' <<<"$latest")" -eq 0 ]]; then
    log "::error::No upstream release matches policy '${FILTER_POLICY_NAME}' version '${FILTER_POLICY_VERSION:-<latest>}'"
    exit 1
  fi
fi

matrix='[]'

while read -r entry; do
  policy_name=$(jq -r '.policy_name' <<<"$entry")
  version=$(jq -r '.version' <<<"$entry")
  tag=$(jq -r '.tag' <<<"$entry")

  if is_excluded "$policy_name"; then
    log "skip ${tag}: policy is excluded from publishing"
    continue
  fi

  if jq -e --arg tag "$tag" 'any(.[]; . == $tag)' <<<"$released" >/dev/null; then
    log "skip ${tag}: already released in ${DEST_REPOSITORY}"
    continue
  fi

  # The policy id is the last segment of the ociUrl annotation and frequently
  # differs from the directory name, so it has to be read from the upstream
  # metadata at the exact tag being repackaged.
  metadata=$(gh api \
    -H "Accept: application/vnd.github.raw+json" \
    "repos/${UPSTREAM_REPOSITORY}/contents/policies/${policy_name}/metadata.yml?ref=${tag}" 2>/dev/null) || {
    log "::error::Cannot read policies/${policy_name}/metadata.yml at ${tag}"
    exit 1
  }

  oci_url=$(yq -r '.annotations."io.kubewarden.policy.ociUrl"' <<<"$metadata")
  metadata_version=$(yq -r '.annotations."io.kubewarden.policy.version"' <<<"$metadata")
  policy_id="${oci_url##*/}"

  if [[ -z "$policy_id" || "$policy_id" == "null" ]]; then
    log "::error::${tag}: the io.kubewarden.policy.ociUrl annotation is missing or empty"
    exit 1
  fi

  if [[ "$metadata_version" != "$version" ]]; then
    log "::error::${tag}: tag version '${version}' does not match the metadata version '${metadata_version}'"
    exit 1
  fi

  log "queue ${tag} (policy id: ${policy_id})"
  matrix=$(jq -c --argjson entry "$entry" --arg policy_id "$policy_id" \
    '. + [$entry + {policy_id: $policy_id}]' <<<"$matrix")
done < <(jq -c '.[]' <<<"$latest")

log "Queued $(jq 'length' <<<"$matrix") policy releases"
echo "$matrix"

#!/usr/bin/env bash
#
# Regression tests for the helper scripts.
#
# These run without network access and without any Kubewarden tooling, so they
# are cheap enough to run on every pull request. They cover the logic that
# decides what gets published and the guards that decide what is allowed to
# change, because a silent failure in either would ship a wrong artifact.

set -euo pipefail

cd "$(dirname "$0")/.."

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

passed=0
failed=0

ok() {
  echo "  PASS: $1"
  passed=$((passed + 1))
}

ko() {
  echo "  FAIL: $1" >&2
  failed=$((failed + 1))
}

check() {
  local description="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    ok "$description"
  else
    ko "$description"
    echo "    expected: $expected" >&2
    echo "    actual:   $actual" >&2
  fi
}

# ---------------------------------------------------------------------------
echo "release selection"
# ---------------------------------------------------------------------------

# The filtering and "latest version" logic from discover-releases.sh. Keep this
# expression identical to the one in that script.
select_latest() {
  jq -c '
    [ .[][]
      | select(.draft == false)
      | select(.prerelease == false)
      | select(.tag_name | test("^[^/]+/v[0-9]+\\.[0-9]+\\.[0-9]+"))
      | {
          tag: .tag_name,
          policy_name: (.tag_name | split("/")[0]),
          version: (.tag_name | split("/")[1] | ltrimstr("v"))
        }
      | select(.version | test("-(alpha|beta|rc)") | not)
    ]
    | group_by(.policy_name)
    | map(sort_by(.version | split(".") | map(tonumber? // 0)) | last)
    | sort_by(.policy_name)
    | map(.tag)'
}

cat > "$WORKDIR/releases.json" <<'JSON'
[[
  {"tag_name": "pod-privileged-policy/v1.0.9",  "draft": false, "prerelease": false},
  {"tag_name": "pod-privileged-policy/v1.0.13", "draft": false, "prerelease": false},
  {"tag_name": "pod-privileged-policy/v1.0.2",  "draft": false, "prerelease": false},
  {"tag_name": "cel-policy/v1.2.0-rc1",         "draft": false, "prerelease": false},
  {"tag_name": "cel-policy/v1.1.0",             "draft": false, "prerelease": false},
  {"tag_name": "echo/v2.0.0",                   "draft": true,  "prerelease": false},
  {"tag_name": "labels-policy/v0.2.0",          "draft": false, "prerelease": true},
  {"tag_name": "v1.0.0",                        "draft": false, "prerelease": false}
]]
JSON

check "picks the highest version numerically, not lexicographically" \
  '["cel-policy/v1.1.0","pod-privileged-policy/v1.0.13"]' \
  "$(select_latest < "$WORKDIR/releases.json")"

# ---------------------------------------------------------------------------
echo "metadata adaptation"
# ---------------------------------------------------------------------------

cat > "$WORKDIR/upstream-metadata.yml" <<'YAML'
rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    operations: ["CREATE", "UPDATE"]
mutating: false
contextAware: false
executionMode: kubewarden-wapc
protocolVersion: V1
annotations:
  io.artifacthub.displayName: Pod Privileged Policy
  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/pod-privileged
  io.kubewarden.policy.title: pod-privileged-policy
  io.kubewarden.policy.version: 1.0.13
  io.kubewarden.policy.author: Kubewarden developers <upstream@example.com>
  io.kubewarden.policy.url: https://github.com/kubewarden/policies
  io.kubewarden.policy.source: https://github.com/kubewarden/policies
  io.kubewarden.policy.usage: |
    line one
    line two
YAML

POLICY_ID=pod-privileged \
UPSTREAM_TAG=pod-privileged-policy/v1.0.13 \
UPSTREAM_DIGEST=sha256:cafe \
UPSTREAM_RELEASE_URL=https://example.com/release \
  ./hack/adapt-metadata.sh "$WORKDIR/upstream-metadata.yml" "$WORKDIR/suse-metadata.yml"

check "repoints the ociUrl at the destination registry" \
  "ghcr.io/rancher/suse-security-policies/pod-privileged" \
  "$(yq -r '.annotations."io.kubewarden.policy.ociUrl"' "$WORKDIR/suse-metadata.yml")"

check "leaves the policy version untouched" \
  "1.0.13" \
  "$(yq -r '.annotations."io.kubewarden.policy.version"' "$WORKDIR/suse-metadata.yml")"

check "preserves the multi-line usage annotation" \
  "line one
line two" \
  "$(yq -r '.annotations."io.kubewarden.policy.usage"' "$WORKDIR/suse-metadata.yml")"

check "records the upstream digest" \
  "sha256:cafe" \
  "$(yq -r '.annotations."com.suse.policy.upstream.digest"' "$WORKDIR/suse-metadata.yml")"

# ---------------------------------------------------------------------------
echo "metadata guard"
# ---------------------------------------------------------------------------

guard() {
  ./hack/check-metadata-diff.sh "$WORKDIR/upstream-metadata.yml" "$1" >/dev/null 2>&1 \
    && echo accepted || echo rejected
}

check "accepts the legitimate adaptation" \
  "accepted" "$(guard "$WORKDIR/suse-metadata.yml")"

# kwctl stamps the module with the version of the tool that annotated it. The
# key is "io.kubewarden.kwctl", which is the name the policy evaluator uses.
yq '.annotations."io.kubewarden.kwctl" = "1.35.0"' \
  "$WORKDIR/suse-metadata.yml" > "$WORKDIR/kwctl-stamp.yml"
check "accepts the kwctl version stamp" \
  "accepted" "$(guard "$WORKDIR/kwctl-stamp.yml")"

# A module that kept the upstream metadata section reads back with the
# upstream values. The guard cannot see this, because it compares the two
# files and they are then equal. The workflow has a separate check for it.
# This test records what the guard does, so the behaviour stays visible.
check "cannot see a module that kept the upstream metadata" \
  "accepted" "$(guard "$WORKDIR/upstream-metadata.yml")"

yq '.mutating = true' "$WORKDIR/suse-metadata.yml" > "$WORKDIR/mutating.yml"
check "rejects a flipped mutating flag" \
  "rejected" "$(guard "$WORKDIR/mutating.yml")"

yq '.rules[0].operations += ["DELETE"]' "$WORKDIR/suse-metadata.yml" > "$WORKDIR/rules.yml"
check "rejects tampered rules" \
  "rejected" "$(guard "$WORKDIR/rules.yml")"

yq '.contextAware = true' "$WORKDIR/suse-metadata.yml" > "$WORKDIR/ctx.yml"
check "rejects a flipped contextAware flag" \
  "rejected" "$(guard "$WORKDIR/ctx.yml")"

yq '.annotations."io.kubewarden.policy.version" = "9.9.9"' \
  "$WORKDIR/suse-metadata.yml" > "$WORKDIR/version.yml"
check "rejects a silently bumped version" \
  "rejected" "$(guard "$WORKDIR/version.yml")"

yq 'del(.annotations."io.artifacthub.displayName")' \
  "$WORKDIR/suse-metadata.yml" > "$WORKDIR/dropped.yml"
check "rejects a dropped annotation" \
  "rejected" "$(guard "$WORKDIR/dropped.yml")"

# ---------------------------------------------------------------------------
echo "repackaged metadata check"
# ---------------------------------------------------------------------------

repackaged_check() {
  POLICY_ID=pod-privileged UPSTREAM_DIGEST=sha256:cafe \
    ./hack/check-repackaged-metadata.sh "$1" >/dev/null 2>&1 \
    && echo accepted || echo rejected
}

check "accepts the adapted metadata" \
  "accepted" "$(repackaged_check "$WORKDIR/suse-metadata.yml")"

# This is the case the diff guard cannot see. A module that kept the metadata
# section of the upstream module reads back with the upstream values.
check "rejects metadata that still points at the upstream registry" \
  "rejected" "$(repackaged_check "$WORKDIR/upstream-metadata.yml")"

yq 'del(.annotations."com.suse.policy.upstream.digest")' \
  "$WORKDIR/suse-metadata.yml" > "$WORKDIR/no-digest.yml"
check "rejects metadata without the upstream digest" \
  "rejected" "$(repackaged_check "$WORKDIR/no-digest.yml")"

yq '.annotations."com.suse.policy.upstream.digest" = "sha256:0000"' \
  "$WORKDIR/suse-metadata.yml" > "$WORKDIR/wrong-digest.yml"
check "rejects metadata that records another digest" \
  "rejected" "$(repackaged_check "$WORKDIR/wrong-digest.yml")"

# ---------------------------------------------------------------------------
echo "changelog rendering"
# ---------------------------------------------------------------------------

cat > "$WORKDIR/body.md" <<'MARKDOWN'
- chore(deps): update the SDK (#582)
- fix: handle the empty case (#577) thanks @viccuad
- feat: see also kubewarden/policy-server#99
- docs: https://example.com/page#anchor and user@example.com
MARKDOWN

POLICY_NAME=pod-privileged-policy \
POLICY_ID=pod-privileged \
POLICY_VERSION=1.0.13 \
UPSTREAM_TAG=pod-privileged-policy/v1.0.13 \
UPSTREAM_RELEASE_URL=https://example.com/release \
UPSTREAM_DIGEST=sha256:cafe \
DEST_OCI_REF=ghcr.io/rancher/suse-security-policies/pod-privileged:v1.0.13 \
  ./hack/render-changelog.sh "$WORKDIR/body.md" > "$WORKDIR/notes.md"

notes=$(cat "$WORKDIR/notes.md")

contains() {
  if grep -qF "$2" <<<"$notes"; then ok "$1"; else ko "$1"; fi
}
excludes() {
  if grep -qF "$2" <<<"$notes"; then ko "$1"; else ok "$1"; fi
}

contains "qualifies bare pull request references" "(kubewarden/policies#582)"
# shellcheck disable=SC2016 # the backticks are literal Markdown, not a subshell
contains "escapes mentions" '`@viccuad`'
contains "leaves already qualified references alone" "kubewarden/policy-server#99"
contains "leaves URL fragments alone" "https://example.com/page#anchor"
contains "leaves email addresses alone" "user@example.com"
excludes "does not double qualify references" "kubewarden/policies#kubewarden"

# ---------------------------------------------------------------------------
echo "sbom adaptation"
# ---------------------------------------------------------------------------

cat > "$WORKDIR/sbom.json" <<'JSON'
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "upstream",
  "documentNamespace": "https://anchore.com/syft/dir/upstream",
  "creationInfo": {"creators": ["Organization: Anchore, Inc", "Tool: syft-1.28.0"]},
  "packages": [
    {"SPDXID": "SPDXRef-Root", "name": "pod-privileged-policy", "downloadLocation": "NOASSERTION"},
    {"SPDXID": "SPDXRef-Dep",  "name": "serde", "downloadLocation": "NOASSERTION"}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Root", "relationshipType": "DESCRIBES"}
  ]
}
JSON

POLICY_ID=pod-privileged \
POLICY_VERSION=1.0.13 \
UPSTREAM_TAG=pod-privileged-policy/v1.0.13 \
UPSTREAM_REPOSITORY_URL=https://github.com/kubewarden/policies \
  ./hack/adapt-sbom.sh "$WORKDIR/sbom.json" "$WORKDIR/sbom.out.json"

check "sets the supplier on the described package" \
  "Organization: SUSE" \
  "$(jq -r '.packages[] | select(.SPDXID == "SPDXRef-Root") | .supplier' "$WORKDIR/sbom.out.json")"

check "leaves dependency packages untouched" \
  "NOASSERTION" \
  "$(jq -r '.packages[] | select(.SPDXID == "SPDXRef-Dep") | .downloadLocation' "$WORKDIR/sbom.out.json")"

check "keeps the upstream creator attributable" \
  "true" \
  "$(jq -r '[.creationInfo.creators[] | select(. == "Tool: syft-1.28.0")] | length == 1' "$WORKDIR/sbom.out.json")"

check "adds SUSE as a creator" \
  "true" \
  "$(jq -r '[.creationInfo.creators[] | select(. == "Organization: SUSE")] | length == 1' "$WORKDIR/sbom.out.json")"

check "regenerates the document namespace" \
  "false" \
  "$(jq -r '.documentNamespace == "https://anchore.com/syft/dir/upstream"' "$WORKDIR/sbom.out.json")"

check "records the upstream document hash" \
  "true" \
  "$(jq -r --arg sha "$(sha256sum "$WORKDIR/sbom.json" | cut -d' ' -f1)" \
     '.comment | contains($sha)' "$WORKDIR/sbom.out.json")"

check "does not touch the relationships" \
  "true" \
  "$(jq --slurpfile a "$WORKDIR/sbom.json" -r \
     '.relationships == $a[0].relationships' "$WORKDIR/sbom.out.json")"

# ---------------------------------------------------------------------------
echo
echo "passed: ${passed}, failed: ${failed}"
[[ "$failed" -eq 0 ]]

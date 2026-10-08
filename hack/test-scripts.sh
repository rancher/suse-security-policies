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
echo "sbom generation"
# ---------------------------------------------------------------------------

# Modelled on what upstream actually publishes: a single syft directory root
# package, the upstream git commit in versionInfo and no licence data at all.
# An invented fixture would hide the shape the generator has to cope with.
cat > "$WORKDIR/upstream-sbom.json" <<'JSON'
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "pod-privileged-1.0.13",
  "documentNamespace": "https://anchore.com/syft/dir/pod-privileged-1.0.13-7f488e6b-6b90-4d61-84ee-9b2dafa39547",
  "creationInfo": {
    "created": "2026-09-17T20:34:22Z",
    "creators": ["Organization: Anchore, Inc", "Tool: syft-1.28.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-DocumentRoot-Directory-pod-privileged-1.0.13",
      "name": "pod-privileged-1.0.13",
      "versionInfo": "9249cc8dc50acd480a7395181fcaa1f0f7ac0a75",
      "supplier": "NOASSERTION",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "primaryPackagePurpose": "FILE"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory-pod-privileged-1.0.13",
      "relationshipType": "DESCRIBES"
    }
  ]
}
JSON

printf 'not really a wasm module' > "$WORKDIR/suse-policy.wasm"

DEST_REF="ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:1111222233334444"

generate_sbom() {
  POLICY_ID=pod-privileged \
  POLICY_VERSION=1.0.13 \
  UPSTREAM_TAG=pod-privileged-policy/v1.0.13 \
  UPSTREAM_REPOSITORY=kubewarden/policies \
  UPSTREAM_DIGEST=sha256:aaaabbbbccccdddd \
  WASM_FILE="$WORKDIR/suse-policy.wasm" \
  WASM_ASSET_NAME=suse-policy.wasm \
  DEST_IMMUTABLE_REF="$DEST_REF" \
  GITHUB_REPOSITORY=rancher/suse-security-policies \
  GITHUB_SHA=0123456789abcdef \
    ./hack/generate-sbom.sh "$1" "$2"
}

generate_sbom "$WORKDIR/upstream-sbom.json" "$WORKDIR/suse-sbom.json" 2> /dev/null

suse_sbom() { jq -r "$1" "$WORKDIR/suse-sbom.json"; }

upstream_sha256=$(sha256sum "$WORKDIR/upstream-sbom.json" | cut -d' ' -f1)
wasm_sha256=$(sha256sum "$WORKDIR/suse-policy.wasm" | cut -d' ' -f1)

check "names the document after the policy and version" \
  "pod-privileged-1.0.13" "$(suse_sbom .name)"

check "builds the namespace from the configured base" \
  "true" \
  "$(suse_sbom '.documentNamespace | startswith("https://github.com/rancher/suse-security-policies/spdx/pod-privileged/1.0.13-")')"

# The namespace must be unique per document, so two runs must not collide.
generate_sbom "$WORKDIR/upstream-sbom.json" "$WORKDIR/suse-sbom-again.json" 2> /dev/null
check "gives every generated document a fresh namespace" \
  "false" \
  "$(jq -r --slurpfile a "$WORKDIR/suse-sbom-again.json" \
     '.documentNamespace == $a[0].documentNamespace' "$WORKDIR/suse-sbom.json")"

check "credits SUSE and the generator commit" \
  '["Organization: SUSE","Tool: suse-security-policies-0123456789abcdef"]' \
  "$(jq -c '.creationInfo.creators' "$WORKDIR/suse-sbom.json")"

check "references the upstream document by namespace" \
  "https://anchore.com/syft/dir/pod-privileged-1.0.13-7f488e6b-6b90-4d61-84ee-9b2dafa39547" \
  "$(suse_sbom '.externalDocumentRefs[0].spdxDocument')"

check "binds the upstream reference with its sha256" \
  "$upstream_sha256" \
  "$(suse_sbom '.externalDocumentRefs[0].checksum.checksumValue')"

check "records the sha256 of the module it describes" \
  "$wasm_sha256" \
  "$(suse_sbom '.packages[0].checksums[0].checksumValue')"

check "describes exactly one package" "1" "$(suse_sbom '.packages | length')"

check "marks the package as an application" \
  "APPLICATION" "$(suse_sbom '.packages[0].primaryPackagePurpose')"

check "does not claim to have analysed the files" \
  "false" "$(suse_sbom '.packages[0].filesAnalyzed')"

# SPDX separates the party that distributes an artifact from the party that
# created its content. Getting these the wrong way round would credit SUSE
# with work it did not do.
check "names SUSE as the supplier" \
  "Organization: SUSE" "$(suse_sbom '.packages[0].supplier')"

check "names Kubewarden as the originator" \
  "true" \
  "$(suse_sbom '.packages[0].originator | startswith("Organization: Kubewarden")')"

check "points the purl at the pushed artifact" \
  "pkg:oci/pod-privileged@sha256:1111222233334444?repository_url=ghcr.io/rancher/suse-security-policies" \
  "$(suse_sbom '.packages[0].externalRefs[0].referenceLocator')"

check "points downloadLocation at the release asset" \
  "https://github.com/rancher/suse-security-policies/releases/download/pod-privileged-policy/v1.0.13/suse-policy.wasm" \
  "$(suse_sbom '.packages[0].downloadLocation')"

# The upstream git commit is the most precise provenance upstream publishes,
# and it only exists in the versionInfo of its root package.
check "carries the upstream source commit" \
  "true" \
  "$(suse_sbom '.packages[0].sourceInfo | contains("9249cc8dc50acd480a7395181fcaa1f0f7ac0a75")')"

check "carries the upstream oci digest" \
  "true" \
  "$(suse_sbom '.packages[0].sourceInfo | contains("sha256:aaaabbbbccccdddd")')"

# The module is not rebuilt, but the metadata section is replaced. Claiming it
# is unmodified without that qualifier would contradict the workflow.
check "does not claim the module is untouched" \
  "true" \
  "$(suse_sbom '.packages[0].sourceInfo | contains("io.kubewarden.metadata custom section was replaced")')"

check "copies the upstream licence conclusion" \
  "NOASSERTION NOASSERTION NOASSERTION" \
  "$(suse_sbom '[.packages[0].licenseConcluded, .packages[0].licenseDeclared, .packages[0].copyrightText] | join(" ")')"

# Licences are repeated, never asserted. If upstream ever concludes one, the
# repackaged document has to follow instead of staying at NOASSERTION.
jq '.packages[0].licenseConcluded = "Apache-2.0" | .packages[0].licenseDeclared = "Apache-2.0"' \
  "$WORKDIR/upstream-sbom.json" > "$WORKDIR/licensed-upstream.json"
generate_sbom "$WORKDIR/licensed-upstream.json" "$WORKDIR/licensed-suse.json" 2> /dev/null
check "follows upstream when it does conclude a licence" \
  "Apache-2.0" \
  "$(jq -r '.packages[0].licenseConcluded' "$WORKDIR/licensed-suse.json")"

check "describes the package it generated" \
  "SPDXRef-Package-pod-privileged" \
  "$(suse_sbom '.relationships[] | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement')"

check "links the package back to the upstream root package" \
  "DocumentRef-upstream:SPDXRef-DocumentRoot-Directory-pod-privileged-1.0.13" \
  "$(suse_sbom '.relationships[] | select(.relationshipType == "GENERATED_FROM") | .relatedSpdxElement')"

# The whole point of the two document split: the file we republish has to stay
# the one upstream signed.
check "leaves the upstream document untouched" \
  "$upstream_sha256" \
  "$(sha256sum "$WORKDIR/upstream-sbom.json" | cut -d' ' -f1)"

generation_fails() {
  if generate_sbom "$1" "$WORKDIR/unused.json" > /dev/null 2>&1; then
    echo "generated"
  else
    echo "failed"
  fi
}

# A GENERATED_FROM relationship has to point at exactly one element. Guessing
# a root would make the document claim a provenance nobody checked.
jq '.relationships = []' "$WORKDIR/upstream-sbom.json" > "$WORKDIR/no-root.json"
check "fails when the upstream document describes nothing" \
  "failed" "$(generation_fails "$WORKDIR/no-root.json")"

jq '.relationships += [{
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Other",
      "relationshipType": "DESCRIBES"
    }]' "$WORKDIR/upstream-sbom.json" > "$WORKDIR/two-roots.json"
check "fails when the upstream document describes more than one package" \
  "failed" "$(generation_fails "$WORKDIR/two-roots.json")"

jq 'del(.documentNamespace)' "$WORKDIR/upstream-sbom.json" > "$WORKDIR/no-namespace.json"
check "fails when the upstream document cannot be referenced" \
  "failed" "$(generation_fails "$WORKDIR/no-namespace.json")"

# The legacy documentDescribes form is still accepted, because the shape
# depends on the tool that produced the SBOM.
jq 'del(.relationships) | .documentDescribes = ["SPDXRef-DocumentRoot-Directory-pod-privileged-1.0.13"]' \
  "$WORKDIR/upstream-sbom.json" > "$WORKDIR/legacy.json"
generate_sbom "$WORKDIR/legacy.json" "$WORKDIR/legacy-suse.json" 2> /dev/null
check "accepts the legacy documentDescribes form" \
  "DocumentRef-upstream:SPDXRef-DocumentRoot-Directory-pod-privileged-1.0.13" \
  "$(jq -r '.relationships[] | select(.relationshipType == "GENERATED_FROM") | .relatedSpdxElement' \
     "$WORKDIR/legacy-suse.json")"

# ---------------------------------------------------------------------------
echo "sbom verification"
# ---------------------------------------------------------------------------

# sbom-utility is not on a developer machine by default. The schema check is
# covered in CI, where the pinned binary is installed.
verify_sbom() {
  local suse="${1:-$WORKDIR/suse-sbom.json}"
  local upstream="${2:-$WORKDIR/upstream-sbom.json}"
  local wasm="${3:-$WORKDIR/suse-policy.wasm}"
  local ref="${4:-$DEST_REF}"

  if SKIP_SCHEMA_CHECK=true \
     POLICY_ID=pod-privileged \
     DEST_IMMUTABLE_REF="$ref" \
       ./hack/verify-sbom.sh "$suse" "$upstream" "$wasm" > /dev/null 2>&1; then
    echo "accepted"
  else
    echo "rejected"
  fi
}

check "accepts the document it generated" "accepted" "$(verify_sbom)"

printf 'a different module' > "$WORKDIR/tampered.wasm"
check "rejects a module that is not the one described" \
  "rejected" "$(verify_sbom "" "" "$WORKDIR/tampered.wasm")"

jq '.name = "tampered"' "$WORKDIR/upstream-sbom.json" > "$WORKDIR/tampered-upstream.json"
check "rejects an upstream document that is not the referenced one" \
  "rejected" "$(verify_sbom "" "$WORKDIR/tampered-upstream.json")"

check "rejects a document that points at another digest" \
  "rejected" \
  "$(verify_sbom "" "" "" "ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:9999")"

jq '.packages[0].checksums[0].checksumValue = "0000"' \
  "$WORKDIR/suse-sbom.json" > "$WORKDIR/wrong-checksum.json"
check "rejects a document whose package checksum was edited" \
  "rejected" "$(verify_sbom "$WORKDIR/wrong-checksum.json")"

jq '.relationships = [ .relationships[]
      | select(.relationshipType == "GENERATED_FROM")
      | .relatedSpdxElement = "DocumentRef-upstream:SPDXRef-Missing" ]
    + [ .relationships[] | select(.relationshipType == "DESCRIBES") ]' \
  "$WORKDIR/suse-sbom.json" > "$WORKDIR/dangling.json"
check "rejects a provenance link that does not resolve upstream" \
  "rejected" "$(verify_sbom "$WORKDIR/dangling.json")"

jq '.externalDocumentRefs[0].spdxDocument = "https://example.com/other"' \
  "$WORKDIR/suse-sbom.json" > "$WORKDIR/wrong-namespace.json"
check "rejects a reference to a different upstream namespace" \
  "rejected" "$(verify_sbom "$WORKDIR/wrong-namespace.json")"


# ---------------------------------------------------------------------------
echo
echo "passed: ${passed}, failed: ${failed}"
[[ "$failed" -eq 0 ]]

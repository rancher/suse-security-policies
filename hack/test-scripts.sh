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
echo "release discovery"
# ---------------------------------------------------------------------------

# A fake gh answers the three API calls of discover-releases.sh from files, so
# the script runs end to end without network access. If the destination
# fixture is missing, the fake fails the call like an API error does.
mkdir -p "$WORKDIR/bin" "$WORKDIR/gh"
cat > "$WORKDIR/bin/gh" <<'SH'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    repos/kubewarden/policies/releases) cat "$GH_FIXTURES/upstream.json"; exit 0 ;;
    repos/rancher/suse-security-policies/releases)
      [[ -f "$GH_FIXTURES/dest.json" ]] || { echo "HTTP 502" >&2; exit 1; }
      cat "$GH_FIXTURES/dest.json"; exit 0 ;;
    repos/kubewarden/policies/contents/policies/*/metadata.yml\?ref=*/v*)
      version="${arg##*/v}"
      printf 'annotations:\n  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/some-id\n  io.kubewarden.policy.version: %s\n' "$version"
      exit 0 ;;
  esac
done
echo "unexpected gh call: $*" >&2
exit 1
SH
chmod +x "$WORKDIR/bin/gh"

cat > "$WORKDIR/gh/upstream.json" <<'JSON'
[[
  {"tag_name": "pod-privileged-policy/v1.0.13", "draft": false, "prerelease": false, "html_url": "https://example.com/1"},
  {"tag_name": "cel-policy/v1.1.0",             "draft": false, "prerelease": false, "html_url": "https://example.com/2"}
]]
JSON

cat > "$WORKDIR/gh/dest.json" <<'JSON'
[[
  {"tag_name": "pod-privileged-policy/v1.0.13"}
]]
JSON

discover() {
  PATH="$WORKDIR/bin:$PATH" \
  GH_FIXTURES="$WORKDIR/gh" \
  DEST_REPOSITORY=rancher/suse-security-policies \
  FORCE="${1:-false}" \
  FILTER_POLICY_NAME="${2:-}" \
    ./hack/discover-releases.sh 2> /dev/null | jq -c 'map(.tag)'
}

check "skips the releases that already exist here" \
  '["cel-policy/v1.1.0"]' "$(discover)"

check "queues an existing release when forced" \
  '["pod-privileged-policy/v1.0.13"]' "$(discover true pod-privileged-policy)"

# A forced run republishes every queued release, and a republish deletes the
# existing release. Without a name, that would hit every policy at once.
check "refuses force without a policy name" \
  "failed" \
  "$(if discover true > /dev/null; then echo queued; else echo failed; fi)"

rm "$WORKDIR/gh/dest.json"

# An API error must not read as "no release here". That would queue a
# republish that deletes the existing release.
check "fails when the releases here cannot be listed" \
  "failed" \
  "$(if discover > /dev/null; then echo queued; else echo failed; fi)"

check "does not list the releases here when forced" \
  '["pod-privileged-policy/v1.0.13"]' "$(discover true pod-privileged-policy)"

# ---------------------------------------------------------------------------
echo "metadata annotations"
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

annotation_args() {
  POLICY_ID=pod-privileged \
  UPSTREAM_TAG=pod-privileged-policy/v1.0.13 \
  UPSTREAM_DIGEST=sha256:cafe \
  UPSTREAM_RELEASE_URL="${1:-https://example.com/release}" \
  UPSTREAM_METADATA="${2:-$WORKDIR/upstream-metadata.yml}" \
    ./hack/annotation-args.sh
}

annotation_args > "$WORKDIR/annotations.txt"

annotation() { grep "^$1=" "$WORKDIR/annotations.txt" | cut -d= -f2-; }

check "emits only the allowlisted provenance annotations" \
  "com.suse.policy.upstream.author
com.suse.policy.upstream.digest
com.suse.policy.upstream.release-url
com.suse.policy.upstream.repository
com.suse.policy.upstream.tag
io.kubewarden.policy.author
io.kubewarden.policy.ociUrl
io.kubewarden.policy.url" \
  "$(cut -d= -f1 "$WORKDIR/annotations.txt" | sort)"

check "repoints the ociUrl at the destination registry" \
  "ghcr.io/rancher/suse-security-policies/pod-privileged" \
  "$(annotation io.kubewarden.policy.ociUrl)"

check "records the upstream digest" \
  "sha256:cafe" "$(annotation com.suse.policy.upstream.digest)"

check "names SUSE as the author" \
  "SUSE <containers@suse.com>" "$(annotation io.kubewarden.policy.author)"

# The author annotation names SUSE, so the upstream author must stay in the
# module under another key.
check "records the upstream author" \
  "Kubewarden developers <upstream@example.com>" \
  "$(annotation com.suse.policy.upstream.author)"

yq 'del(.annotations."io.kubewarden.policy.author")' \
  "$WORKDIR/upstream-metadata.yml" > "$WORKDIR/upstream-no-author.yml"
check "fails when the upstream module has no author" \
  "failed" \
  "$(if annotation_args https://example.com/release "$WORKDIR/upstream-no-author.yml" \
       > /dev/null 2>&1; then echo emitted; else echo failed; fi)"

check "keeps everything after the first '=' in the value" \
  "https://example.com/release?a=b" \
  "$(annotation_args 'https://example.com/release?a=b' | grep '^com.suse.policy.upstream.release-url=' | cut -d= -f2-)"

annotation_args_result() {
  if annotation_args "$1" > /dev/null 2>&1; then echo "emitted"; else echo "failed"; fi
}

# kwctl reads KEY=@PATH as a file path. Thus kwctl reads a file instead of
# using the value as text.
check "rejects a value kwctl would read as a file" \
  "failed" "$(annotation_args_result '@/etc/passwd')"

check "rejects a value with a newline" \
  "failed" "$(annotation_args_result $'https://example.com\nrelease')"

check "fails when a required variable is missing" \
  "failed" \
  "$(if UPSTREAM_DIGEST='' POLICY_ID=x UPSTREAM_TAG=x UPSTREAM_RELEASE_URL=x \
       ./hack/annotation-args.sh > /dev/null 2>&1; then echo emitted; else echo failed; fi)"

# The workflow gives these pairs to kwctl, and kwctl changes the metadata of the
# module. The tests below apply the same pairs with yq. Thus the tests of the
# metadata checks run without kwctl.
cp "$WORKDIR/upstream-metadata.yml" "$WORKDIR/suse-metadata.yml"
while IFS= read -r pair; do
  KEY="${pair%%=*}" VALUE="${pair#*=}" \
    yq -i '.annotations[strenv(KEY)] = strenv(VALUE)' "$WORKDIR/suse-metadata.yml"
done < "$WORKDIR/annotations.txt"

check "leaves the policy version untouched" \
  "1.0.13" \
  "$(yq -r '.annotations."io.kubewarden.policy.version"' "$WORKDIR/suse-metadata.yml")"

check "preserves the multi-line usage annotation" \
  "line one
line two" \
  "$(yq -r '.annotations."io.kubewarden.policy.usage"' "$WORKDIR/suse-metadata.yml")"

# This repository holds no source code, so the source annotation must keep
# pointing at upstream.
check "leaves the source annotation untouched" \
  "https://github.com/kubewarden/policies" \
  "$(yq -r '.annotations."io.kubewarden.policy.source"' "$WORKDIR/suse-metadata.yml")"

# ---------------------------------------------------------------------------
echo "upstream metadata check"
# ---------------------------------------------------------------------------

upstream_check() {
  POLICY_ID="${2:-pod-privileged}" POLICY_VERSION="${3:-1.0.13}" \
    ./hack/check-upstream-metadata.sh "$1" >/dev/null 2>&1 \
    && echo accepted || echo rejected
}

check "accepts the module of the release" \
  "accepted" "$(upstream_check "$WORKDIR/upstream-metadata.yml")"

check "rejects a module with another version" \
  "rejected" "$(upstream_check "$WORKDIR/upstream-metadata.yml" pod-privileged 1.0.14)"

check "rejects a module of another policy" \
  "rejected" "$(upstream_check "$WORKDIR/upstream-metadata.yml" host-namespaces-psp 1.0.13)"

yq 'del(.annotations."io.kubewarden.policy.version")' \
  "$WORKDIR/upstream-metadata.yml" > "$WORKDIR/upstream-no-version.yml"
check "rejects a module without a version" \
  "rejected" "$(upstream_check "$WORKDIR/upstream-no-version.yml")"

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
yq '.annotations."io.kubewarden.kwctl" = "1.39.0-rc.1"' \
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

yq '.annotations."io.kubewarden.policy.source" = "https://github.com/rancher/suse-security-policies"' \
  "$WORKDIR/suse-metadata.yml" > "$WORKDIR/source.yml"
check "rejects a changed source annotation" \
  "rejected" "$(guard "$WORKDIR/source.yml")"

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
echo
echo "passed: ${passed}, failed: ${failed}"
[[ "$failed" -eq 0 ]]

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
echo
echo "passed: ${passed}, failed: ${failed}"
[[ "$failed" -eq 0 ]]

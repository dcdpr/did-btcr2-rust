#!/usr/bin/env bash
# Tests advisory-issue.sh against a stub `gh` that records every call and answers
# `gh issue list` by applying the script's own --jq filter to a canned list of open issues.
# Needs bash, jq and coreutils; no network and no token.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
title="Scheduled advisory scan failed"
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

mkdir "$work/bin"
cat > "$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GH_STUB_LOG"
if [ "$1 $2" = "issue list" ]; then
  filter=
  while [ $# -gt 0 ]; do
    if [ "$1" = "--jq" ]; then
      filter=$2
    fi
    shift
  done
  printf '%s' "$GH_STUB_ISSUES" | jq -r "$filter"
fi
STUB
chmod +x "$work/bin/gh"

# Longer than the 60000-byte cap, ending in a sentinel line the tail must keep.
{
  head -c 69000 /dev/zero | tr '\0' 'x'
  printf '\nerror[vulnerability]: sentinel\n'
} > "$work/deny.log"

# run_case <name> <open-issues-json>; the stub's call log is $work/<name>.calls
run_case() {
  mkdir -p "$work/$1.tmp"
  : > "$work/$1.calls"
  PATH="$work/bin:$PATH" TMPDIR="$work/$1.tmp" GH_STUB_LOG="$work/$1.calls" \
    GH_STUB_ISSUES="$2" GITHUB_SHA=abc123 RUN_URL=https://example.invalid/run \
    GH_REPO=o/r GH_TOKEN=x bash "$here/advisory-issue.sh" "$work/deny.log" \
    || fail "$1: script exited non-zero"
}

expect_create() {
  grep -q "^issue create --title $title --body-file " "$work/$1.calls" || fail "$1: no issue create"
  if grep -q '^issue edit' "$work/$1.calls"; then fail "$1: unexpected issue edit"; fi
}

expect_edit() {
  grep -q "^issue edit $2 --body-file " "$work/$1.calls" || fail "$1: no issue edit $2"
  if grep -q '^issue create' "$work/$1.calls"; then fail "$1: unexpected issue create"; fi
}

run_case none '[]'
expect_create none

run_case similar-title-only '[{"number":7,"title":"Scheduled advisory scan failed again"}]'
expect_create similar-title-only

run_case exact-among-similar '[{"number":7,"title":"Scheduled advisory scan failed again"},{"number":9,"title":"Scheduled advisory scan failed"}]'
expect_edit exact-among-similar 9

run_case exact-only '[{"number":42,"title":"Scheduled advisory scan failed"}]'
expect_edit exact-only 42

body=$(sed -n 's/^issue create .* --body-file //p' "$work/none.calls")
if [ -n "$body" ] && [ -f "$body" ]; then
  for want in abc123 https://example.invalid/run 'error[vulnerability]: sentinel'; do
    grep -qF "$want" "$body" || fail "body lacks $want"
  done
  size=$(wc -c < "$body")
  [ "$size" -lt 61000 ] || fail "body is $size bytes, expected under 61000"
else
  fail "body file not found"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "advisory-issue.sh: all cases passed"

#!/usr/bin/env bash
# Tests advisory-issue.sh against a stub `gh` that records every call and answers
# `gh issue list` and `gh issue view` by applying the script's own --jq filter to a canned
# list of open issues and a canned issue body.
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
cmd="$1 $2"
filter=
while [ $# -gt 0 ]; do
  if [ "$1" = "--jq" ]; then
    filter=$2
  fi
  shift
done
if [ "$cmd" = "issue list" ]; then
  printf '%s' "$GH_STUB_ISSUES" | jq -r "$filter"
elif [ "$cmd" = "issue view" ]; then
  jq -n --arg body "$GH_STUB_BODY" '{body: $body}' | jq -r "$filter"
fi
STUB
chmod +x "$work/bin/gh"

# Longer than the 60000-byte cap, ending in a sentinel line the tail must keep. It reports
# RUSTSEC-2026-0001 and RUSTSEC-2026-0002, one of them twice.
{
  head -c 69000 /dev/zero | tr '\0' 'x'
  printf '\nerror[vulnerability]: RUSTSEC-2026-0002\n'
  printf 'error[vulnerability]: RUSTSEC-2026-0001\n'
  printf 'ID: RUSTSEC-2026-0002\n'
  printf 'error[vulnerability]: sentinel\n'
} > "$work/deny.log"

# run_case <name> <open-issues-json> [<existing-issue-body>]; the stub's call log is
# $work/<name>.calls
run_case() {
  mkdir -p "$work/$1.tmp"
  : > "$work/$1.calls"
  PATH="$work/bin:$PATH" TMPDIR="$work/$1.tmp" GH_STUB_LOG="$work/$1.calls" \
    GH_STUB_ISSUES="$2" GH_STUB_BODY="${3-}" GITHUB_SHA=abc123 \
    RUN_URL=https://example.invalid/run GH_REPO=o/r GH_TOKEN=x \
    bash "$here/advisory-issue.sh" "$work/deny.log" \
    || fail "$1: script exited non-zero"
}

expect_create() {
  grep -q "^issue create --title $title --body-file " "$work/$1.calls" || fail "$1: no issue create"
  if grep -q '^issue edit' "$work/$1.calls"; then fail "$1: unexpected issue edit"; fi
  if grep -q '^issue comment' "$work/$1.calls"; then fail "$1: unexpected issue comment"; fi
}

expect_comment() {
  grep -q "^issue comment $2 --body .*$3" "$work/$1.calls" || fail "$1: no issue comment $2 naming $3"
}

expect_no_comment() {
  if grep -q '^issue comment' "$work/$1.calls"; then fail "$1: unexpected issue comment"; fi
}

expect_edit() {
  grep -q "^issue edit $2 --body-file " "$work/$1.calls" || fail "$1: no issue edit $2"
  if grep -q '^issue create' "$work/$1.calls"; then fail "$1: unexpected issue create"; fi
}

run_case none '[]'
expect_create none

bot='"author":{"login":"app/github-actions"}'
other='"author":{"login":"someone"}'

run_case similar-title-only "[{\"number\":7,\"title\":\"$title again\",$bot}]"
expect_create similar-title-only

run_case exact-among-similar "[{\"number\":7,\"title\":\"$title again\",$bot},{\"number\":9,\"title\":\"$title\",$bot}]"
expect_edit exact-among-similar 9

run_case exact-only "[{\"number\":42,\"title\":\"$title\",$bot}]"
expect_edit exact-only 42

# An issue with the exact title that someone else opened is not the workflow's to edit.
run_case exact-by-other-author "[{\"number\":5,\"title\":\"$title\",$other}]"
expect_create exact-by-other-author

run_case exact-by-both-authors "[{\"number\":5,\"title\":\"$title\",$other},{\"number\":6,\"title\":\"$title\",$bot}]"
expect_edit exact-by-both-authors 6

# The open issue already reports the same advisories, in another order: edit silently.
run_case same-advisories "[{\"number\":42,\"title\":\"$title\",$bot}]" \
  'old log: RUSTSEC-2026-0001 then RUSTSEC-2026-0002'
expect_edit same-advisories 42
expect_no_comment same-advisories

# A new advisory appeared while the issue was open: edit and comment, which notifies.
run_case new-advisory "[{\"number\":42,\"title\":\"$title\",$bot}]" \
  'old log: RUSTSEC-2026-0001'
expect_edit new-advisory 42
expect_comment new-advisory 42 'RUSTSEC-2026-0001 RUSTSEC-2026-0002'

# An advisory the issue reported is gone: the set changed, so comment.
run_case removed-advisory "[{\"number\":42,\"title\":\"$title\",$bot}]" \
  'old log: RUSTSEC-2025-0099 RUSTSEC-2026-0001 RUSTSEC-2026-0002'
expect_edit removed-advisory 42
expect_comment removed-advisory 42 'RUSTSEC-2026-0001 RUSTSEC-2026-0002'

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

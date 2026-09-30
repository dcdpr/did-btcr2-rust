#!/usr/bin/env bash
# Tests advisory-issue.sh, in both its report and its close mode, against a stub `gh` that
# records every call and answers `gh issue list` and `gh issue view` by applying the script's
# own --jq filter to a canned list of open issues and a canned issue body.
#
# The stub does not implement the query qualifiers of `gh issue list`, so it refuses a call
# that lacks the ones the canned list stands for: `--state open` (the list holds only open
# issues), `--app github-actions` and the exact-title `--search` (gh returns no match for
# `--app` without `--search`, so dropping either would silently find nothing on GitHub).
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
filter= state= app= search=
while [ $# -gt 0 ]; do
  case "$1" in
    --jq) filter=$2 ;;
    --state) state=$2 ;;
    --app) app=$2 ;;
    --search) search=$2 ;;
  esac
  shift
done
if [ "$cmd" = "issue list" ]; then
  want_search="\"$GH_STUB_TITLE\" in:title"
  if [ "$state" != open ] || [ "$app" != github-actions ] || [ "$search" != "$want_search" ]; then
    echo "gh stub: issue list needs --state open, --app github-actions and" \
      "--search '$want_search'; got state='$state' app='$app' search='$search'" >&2
    exit 3
  fi
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

# invoke <name> <open-issues-json> <existing-issue-body> <script-args...>: runs the script
# against the stub, whose call log is $work/<name>.calls, and returns its exit status.
invoke() {
  local name=$1 issues=$2 old_body=$3
  shift 3
  mkdir -p "$work/$name.tmp"
  : > "$work/$name.calls"
  PATH="$work/bin:$PATH" TMPDIR="$work/$name.tmp" GH_STUB_LOG="$work/$name.calls" \
    GH_STUB_ISSUES="$issues" GH_STUB_BODY="$old_body" GH_STUB_TITLE="$title" GITHUB_SHA=abc123 \
    RUN_URL=https://example.invalid/run GH_REPO=o/r GH_TOKEN=x \
    bash "$here/advisory-issue.sh" "$@"
}

# run_case <name> <open-issues-json> [<existing-issue-body>]: a failed scan's report.
run_case() {
  invoke "$1" "$2" "${3-}" report "$work/deny.log" || fail "$1: script exited non-zero"
}

# run_close <name> <open-issues-json>: a passing scan.
run_close() {
  invoke "$1" "$2" "" close || fail "$1: script exited non-zero"
}

# Only the lookup ran: nothing was created, edited, commented on or closed.
expect_untouched() {
  if grep -v '^issue list ' "$work/$1.calls" | grep -q .; then
    fail "$1: unexpected calls: $(grep -v '^issue list ' "$work/$1.calls" | paste -sd ';' -)"
  fi
}

expect_close() {
  grep -q "^issue close $2 --comment .*abc123.*https://example.invalid/run" "$work/$1.calls" \
    || fail "$1: no issue close $2 with a comment naming the commit and the run"
  if grep -v -e '^issue list ' -e "^issue close $2 " "$work/$1.calls" | grep -q .; then
    fail "$1: unexpected calls besides closing $2"
  fi
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

# A passing scan closes the workflow's open issue, with a comment naming the run.
run_close close-open "[{\"number\":42,\"title\":\"$title\",$bot}]"
expect_close close-open 42

# A passing scan with no open issue does nothing beyond the lookup.
run_close close-none '[]'
expect_untouched close-none

# An issue with the exact title that someone else opened is not the workflow's to close.
run_close close-by-other-author "[{\"number\":5,\"title\":\"$title\",$other}]"
expect_untouched close-by-other-author

run_close close-by-both-authors "[{\"number\":5,\"title\":\"$title\",$other},{\"number\":6,\"title\":\"$title\",$bot}]"
expect_close close-by-both-authors 6

# A missing or unknown mode, or a report without its log, is a usage error that calls nothing.
for args in "" "bogus" "report" "close extra"; do
  name="usage-${args// /-}"
  # shellcheck disable=SC2086 # the words of $args are the script's arguments
  if invoke "$name" '[]' "" $args 2> /dev/null; then
    fail "$name: script exited zero"
  fi
  if [ -s "$work/$name.calls" ]; then fail "$name: the stub was called"; fi
done

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

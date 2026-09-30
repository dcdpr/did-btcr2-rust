#!/usr/bin/env bash
# Tracks the scheduled advisory scan in a single GitHub issue.
#
# `report <deny-log>` (the scan failed): creates the issue, or replaces the body of the open
# one the workflow opened earlier with the same title, so a lasting advisory does not open an
# issue a day or notify daily. When the set of RUSTSEC IDs in the report differs from the one
# in the issue, it also comments, so a new advisory notifies.
#
# `close` (the scan passed): closes that open issue, if there is one, with a comment naming
# the passing run, so the next failure opens a fresh issue instead of editing a stale one.
#
# Usage: advisory-issue.sh report <deny-log> | advisory-issue.sh close
# Environment: GH_TOKEN, GH_REPO, RUN_URL, GITHUB_SHA.
set -euo pipefail

usage() {
  echo "usage: $0 report <deny-log> | $0 close" >&2
  exit 2
}

mode=${1-}
case "$mode" in
  report) [ $# -eq 2 ] || usage ;;
  close) [ $# -eq 1 ] || usage ;;
  *) usage ;;
esac

title="Scheduled advisory scan failed"

# The open issue the workflow itself opened, or nothing. Only such an issue counts: anyone can
# open one with this title, and its author could then edit or close the report. `--app`
# narrows the search, and the jq check on the login (which gh reports as
# "app/github-actions") is what enforces it.
number=$(gh issue list --state open --app github-actions --search "\"$title\" in:title" \
  --json number,title,author \
  --jq "map(select(.title == \"$title\" and .author.login == \"app/github-actions\")) | .[0].number // empty")

if [ "$mode" = close ]; then
  if [ -n "$number" ]; then
    gh issue close "$number" --comment "The scheduled advisory scan passed on ${GITHUB_SHA}. \
Run: ${RUN_URL}"
  fi
  exit 0
fi

log=$2
body=$(mktemp)

{
  echo "The daily \`cargo deny check advisories\` run failed on ${GITHUB_SHA}."
  echo
  echo "Run: ${RUN_URL}"
  echo
  echo '```'
  tail -c 60000 "$log"
  echo '```'
} > "$body"

advisory_ids() {
  { grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$1" || true; } | sort -u | paste -sd ' ' -
}

if [ -n "$number" ]; then
  # A body edit notifies nobody. When the reported advisories differ from the ones already in
  # the issue, also comment, since a comment does notify.
  old_body=$(mktemp)
  gh issue view "$number" --json body --jq .body > "$old_body"
  old_ids=$(advisory_ids "$old_body")
  new_ids=$(advisory_ids "$body")
  gh issue edit "$number" --body-file "$body"
  if [ "$old_ids" != "$new_ids" ]; then
    gh issue comment "$number" --body "The reported advisories changed: \
${new_ids:-none found in the log}. Run: ${RUN_URL}"
  fi
else
  gh issue create --title "$title" --body-file "$body"
fi

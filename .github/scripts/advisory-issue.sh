#!/usr/bin/env bash
# Reports a failed scheduled advisory scan as a single GitHub issue: creates it, or replaces
# the body of the open one the workflow opened earlier with the same title, so a lasting
# advisory does not open an issue a day or notify daily. When the set of RUSTSEC IDs in the
# report differs from the one in the issue, it also comments, so a new advisory notifies.
# Usage: advisory-issue.sh <deny-log>
# Environment: GH_TOKEN, GH_REPO, RUN_URL, GITHUB_SHA.
set -euo pipefail

log=$1
title="Scheduled advisory scan failed"
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

# Only an issue the workflow itself opened counts: anyone can open one with this title, and
# its author could then edit or close the report. `--app` narrows the search, and the jq
# check on the login (which gh reports as "app/github-actions") is what enforces it.
number=$(gh issue list --state open --app github-actions --search "\"$title\" in:title" \
  --json number,title,author \
  --jq "map(select(.title == \"$title\" and .author.login == \"app/github-actions\")) | .[0].number // empty")

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

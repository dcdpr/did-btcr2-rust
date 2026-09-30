#!/usr/bin/env bash
# Reports a failed scheduled advisory scan as a single GitHub issue: creates it, or replaces
# the body of the open one with the same title, so a lasting advisory does not open an issue
# a day or notify daily.
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

number=$(gh issue list --state open --search "\"$title\" in:title" \
  --json number,title --jq "map(select(.title == \"$title\")) | .[0].number // empty")

if [ -n "$number" ]; then
  gh issue edit "$number" --body-file "$body"
else
  gh issue create --title "$title" --body-file "$body"
fi

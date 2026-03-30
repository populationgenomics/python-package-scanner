#!/usr/bin/env bash
# Post or update a PR comment with the vulnerability report.
# Uses an HTML marker to identify our comment and avoid clobbering others.
#
# Usage: pr-comment.sh <owner/repo> <pr-number>
# Requires: GH_TOKEN and REPORT environment variables

set -euo pipefail

REPO="$1"
PR_NUMBER="$2"
MARKER="<!-- python-package-scanner -->"

BODY="${MARKER}
${REPORT}"

# Search for an existing comment with our marker
COMMENT_ID=$(
  gh api \
    --paginate \
    "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    --jq ".[] | select(.body | contains(\"${MARKER}\")) | .id" \
  | head -1
)

if [ -n "$COMMENT_ID" ]; then
  # Update existing comment
  gh api \
    --method PATCH \
    "repos/${REPO}/issues/comments/${COMMENT_ID}" \
    -f body="$BODY" \
    --silent
  echo "Updated existing PR comment (ID: ${COMMENT_ID})"
else
  # Create new comment
  gh api \
    --method POST \
    "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    -f body="$BODY" \
    --silent
  echo "Created new PR comment"
fi

#!/usr/bin/env bash
# Rebase onto the remote branch and push the local heal commit.
#
#   GH_TOKEN=... ci_push.sh [BRANCH]
#
# The token lives only in this process's environment (GIT_CONFIG_* env, git >= 2.31): it is
# not written to .git/config, not put in a URL and not in argv. Checkout ran with
# persist-credentials: false, so nothing else on disk carries it.
# Any failure (rebase conflict, protected branch rejecting the push) fails the step with an
# explicit message: the heal commit never reached main, so the run must not be green.
set -u
branch=${1:-main}
: "${GH_TOKEN:?GH_TOKEN is required}"
auth=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
echo "::add-mask::$auth"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=http.extraheader
export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $auth"

if ! git pull --rebase origin "$branch"; then
  git rebase --abort 2>/dev/null || true
  echo "::error::Could not rebase the heal commit onto origin/$branch (conflict or fetch failure). Healed rules were NOT published; failing the run."
  exit 1
fi
if ! git push origin "HEAD:$branch"; then
  echo "::error::Pushing the heal commit to $branch was rejected. If $branch is protected, branch protection must allow the Actions bot (github-actions[bot]) or the workflow must use a PAT. Healed rules were NOT published; failing the run."
  exit 1
fi
echo "Healed rules pushed to $branch"

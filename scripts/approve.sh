#!/usr/bin/env bash
# tfcap approval flow for the GitHub Action. Usage: approve.sh prepare|commit|all
#
#   prepare  read-only job: checks the label and the approver, runs `tfcap lock`
#            on the PR code and stores the result in $RUNNER_TEMP/tfcap-approval
#   commit   write job: never runs PR code. Re-checks the approver, checks the
#            prepared lock file belongs to the PR's current commit, commits only
#            that file, sets the status and updates the PR comment
#   all      both, in one job (simpler; runs PR code with a write token)
set -uo pipefail
step="${1:?usage: approve.sh prepare|commit|all}"
art="$RUNNER_TEMP/tfcap-approval"
comment="$RUNNER_TEMP/tfcap.comment.md"
out() { echo "$1" >> "$GITHUB_OUTPUT"; }
finish() { out "exit-code=$1"; [ -f "$comment" ] && cat "$comment" >> "$GITHUB_STEP_SUMMARY"; exit 0; }
say() { { echo '<!-- tfcap -->'; printf '%s\n' "$@"; } > "$comment"; }

gate() {
  if [ "$EVENT" != "pull_request" ] || [ "$ACTION" != "labeled" ] || [ "$LABEL" != "$APPROVE_LABEL" ]; then
    echo "::notice::approval only runs when the '$APPROVE_LABEL' label is added to a pull request. Nothing to do."
    out "skip-comment=true"; finish 0
  fi
  # Only people who could push the change themselves may approve it.
  perm=$(gh api "repos/$REPO/collaborators/$ACTOR/permission" --jq .permission 2>/dev/null || echo none)
  case "$perm" in
    admin|maintain|write) ;;
    *) say '### tfcap: approval ignored' '' \
         "@$ACTOR added \`$APPROVE_LABEL\`, but approving module changes needs write access to this repository (they have \`$perm\`)."
       finish 1 ;;
  esac
  if [ "$(git rev-parse HEAD)" != "$HEAD_SHA" ]; then
    say '### tfcap: approval not applied' '' \
      "The pull request changed after the label was added, so nothing was approved. Remove and re-add \`$APPROVE_LABEL\` to approve the latest commit."
    finish 1
  fi
}

prepare() {
  lockout=$(tfcap lock . 2>&1); code=$?
  if [ $code -ne 0 ]; then
    say '### tfcap: approval refused' '' "@$ACTOR, the lock file was not updated:" '' '```' "$lockout" '```' '' \
      'A label cannot approve a module whose code changed without a version change. Investigate, and if it is legitimate, run `tfcap lock --accept-mutated` locally and push.'
    finish 1
  fi
  tfcap verify . --fail-on "$FAIL_ON" --no-color > "$RUNNER_TEMP/verify.txt" 2>&1; vcode=$?
  mkdir -p "$art"
  cp tfcap.lock.json "$art/tfcap.lock.json"
  printf '%s\n' "$lockout" > "$art/summary.txt"
  printf '%s\n' "$HEAD_SHA" > "$art/head_sha"
  printf '%s\n' "$vcode" > "$art/verify_code"
  cp "$RUNNER_TEMP/verify.txt" "$art/verify.txt"
}

commit() {
  for f in tfcap.lock.json summary.txt head_sha verify_code; do
    [ -f "$art/$f" ] || { echo "::error::prepared approval is missing $f"; out "skip-comment=true"; finish 2; }
  done
  if [ "$(cat "$art/head_sha")" != "$HEAD_SHA" ]; then
    say '### tfcap: approval not applied' '' 'The prepared lock file was made for a different commit than the pull request now points at. Re-add the label.'
    finish 1
  fi
  # The prepared file comes from a job that ran PR code: accept it only if it
  # is a well-formed tfcap lock file, and commit nothing else.
  if ! tfcap validate-lock "$art/tfcap.lock.json"; then
    say '### tfcap: approval refused' '' 'The prepared lock file is not a valid tfcap lock file.'
    finish 1
  fi
  cp "$art/tfcap.lock.json" tfcap.lock.json
  git add tfcap.lock.json
  staged=$(git diff --cached --name-only)
  want=$(git ls-files --full-name tfcap.lock.json)
  if [ -n "$staged" ] && [ "$staged" != "$want" ]; then
    echo "::error::refusing to commit unexpected changes: $staged"; finish 2
  fi
  if [ -n "$staged" ]; then
    git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
      commit -q -m "tfcap: approve module changes" -m "Approved-by: @$ACTOR (label: $APPROVE_LABEL)" -m "$(cat "$art/summary.txt")"
    git push -q origin "HEAD:$HEAD_REF" || { echo "::error::push failed"; finish 2; }
  fi
  sha=$(git rev-parse HEAD)
  vcode=$(cat "$art/verify_code")
  if [ "$vcode" = 0 ]; then state=success; desc="Module changes approved by @$ACTOR"; else state=failure; desc="Still failing after approval; see the run log"; fi
  # Pushes made with the workflow token do not start new workflow runs, so
  # report the result on the new commit directly.
  gh api -X POST "repos/$REPO/statuses/$sha" -f state="$state" -f context="$STATUS_CONTEXT" -f description="$desc" >/dev/null
  say '### tfcap: module changes approved ✅' '' "Approved by @$ACTOR. \`tfcap.lock.json\` updated in ${sha:0:7}:" '' '```' "$(cat "$art/summary.txt")" '```'
  if [ "$vcode" != 0 ]; then { echo; echo '```'; cat "$art/verify.txt"; echo '```'; } >> "$comment"; fi
  finish "$vcode"
}

case "$step" in
  prepare) gate; prepare; out "approved=true"; out "skip-comment=true"; finish 0 ;;
  commit)  gate; commit ;;
  all)     gate; prepare; commit ;;
  *) echo "::error::unknown step $step"; exit 2 ;;
esac

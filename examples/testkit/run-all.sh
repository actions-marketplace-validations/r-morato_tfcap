#!/bin/sh
# Runs tfcap over every scenario and checks the findings match expect.txt.
# Read-only: scenario 10 is copied to a temp folder before it is modified.
cd "$(dirname "$0")" || exit 2
command -v tfcap >/dev/null 2>&1 || { echo "tfcap not found on PATH"; exit 2; }
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }

for dir in 0*/; do
  dir=${dir%/}
  [ -f "$dir/expect.txt" ] || continue
  echo "$dir"
  json=$(tfcap scan "$dir" --min-severity low --format json)
  while IFS= read -r line; do
    case "$line" in
      =0) if printf '%s' "$json" | grep -q '"rule_id"'; then bad "expected no findings"; else ok "no findings"; fi ;;
      +*) id=${line#+}; if printf '%s' "$json" | grep -q "\"rule_id\": \"$id\""; then ok "$id"; else bad "$id missing"; fi ;;
      -*) id=${line#-}; if printf '%s' "$json" | grep -q "\"rule_id\": \"$id\""; then bad "$id should not appear"; else ok "no $id"; fi ;;
    esac
  done < "$dir/expect.txt"
done

echo "09-upgrade (diff)"
tfcap diff 09-upgrade/before 09-upgrade/after --no-color >/dev/null; code=$?
[ "$code" = 1 ] && ok "diff flags the upgrade (exit 1)" || bad "diff exit $code, want 1"
tfcap diff 09-upgrade/before 09-upgrade/before --no-color >/dev/null; code=$?
[ "$code" = 0 ] && ok "no change, no failure (exit 0)" || bad "diff exit $code, want 0"

echo "10-tag-mutation (lock / verify)"
tmp=$(mktemp -d)
cp -R 10-tag-mutation/. "$tmp/"
tfcap lock "$tmp" >/dev/null
tfcap verify "$tmp" --no-color >/dev/null; code=$?
[ "$code" = 0 ] && ok "verify passes right after lock" || bad "verify exit $code, want 0"
"$tmp/simulate-tag-move.sh" >/dev/null
out=$(tfcap verify "$tmp" --no-color); code=$?
[ "$code" = 1 ] && ok "verify fails after tag move (exit 1)" || bad "verify exit $code, want 1"
printf '%s' "$out" | grep -q MUTATED && ok "reported as MUTATED" || bad "MUTATED missing"
rm -rf "$tmp"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]

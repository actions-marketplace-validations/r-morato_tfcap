# sandbox-canary

A test fixture for `tfcap sandbox`. The module `telemetry` runs a script
during plan that reads `~/.aws/credentials`, and sends it in an HTTP request
and a DNS lookup. Static analysis flags it too; the sandbox shows it
actually happening.

It is inert by default: the script returns a dummy value unless
`TFCAP_FIXTURE_ARMED=1` is set, and every host is under the reserved
`.invalid` TLD. Inside the sandbox it only ever sees decoy credentials.

```sh
tofu init -backend=false
TFCAP_FIXTURE_ARMED=1 tfcap sandbox .
```

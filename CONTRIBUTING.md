# Contributing to tfcap

Thanks for helping. The most valuable contributions are:

1. **Samples.** Sanitized real-world malicious or suspicious modules, so new rules are grounded in what attackers actually do. Make them inert: use the reserved `.invalid` TLD (RFC 2606) for every endpoint, and never include working credentials or payloads.
2. **False positives.** If a popular, legitimate module produces noise, open an issue with the module, version and the finding.
3. **Rules.** New detections with tests.

## Development

```sh
go test ./...
make lint
make demo    # run the upgrade-attack example
make docs    # regenerate docs/rules.md after changing rules
```

## Adding a rule

1. Add an ID and a catalog entry in `internal/rules/rules.go` (ID prefix by area: `EXEC`, `NET`, `FS`, `CRED`, `OBF`, `IAM`, `SRC`, `PROV`).
2. Emit it from `internal/analyze`. Put something stable in `Detail`, without line numbers or versions, because it feeds the fingerprint used by `diff` and `lock`.
3. Add a positive *and* a negative case to `TestRules` in `internal/analyze/analyze_test.go`.
4. Run `make docs`.

Rule IDs are part of the public interface (SARIF, lock files, suppressions), so never renumber or reuse one.

## Pull requests

Keep PRs focused, run `gofmt`, and describe the threat a new rule addresses.

# Security policy

## Reporting a vulnerability in tfcap

Please **do not** open a public issue. Use GitHub's private vulnerability reporting on this repository (Security tab, then "Report a vulnerability"). You should get an acknowledgement within a few days.

In scope: anything that lets a crafted Terraform module make tfcap execute code, read or write files outside the scanned directory, access the network, or reliably hide one of the behaviors tfcap claims to detect (a detection bypass).

## Reporting a malicious Terraform module or provider

If you found malicious code in a public registry module or provider, report it to the registry operator (HashiCorp, the OpenTofu registry, or the module's host) first. Once it's public or taken down, we'd love an inert, sanitized sample for the test suite.

## Design commitments

tfcap only reads files. It never runs Terraform, never executes module code or scripts, and makes no network requests.

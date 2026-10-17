# Security policy

## Reporting a vulnerability in tfcap

Please **do not** open a public issue. Use GitHub's private vulnerability reporting on this repository (Security tab, then "Report a vulnerability"). You should get an acknowledgement within a few days.

In scope: anything that lets a crafted Terraform module make tfcap execute code, read or write files outside the scanned directory, access the network, or reliably hide one of the behaviors tfcap claims to detect (a detection bypass).

## Reporting a malicious Terraform module or provider

If you found malicious code in a public registry module or provider, report it to the registry operator (HashiCorp, the OpenTofu registry, or the module's host) first. Once it's public or taken down, we'd love an inert, sanitized sample for the test suite.

## Design commitments

tfcap only reads files. It never runs Terraform, never executes module code or scripts, and makes no network requests.

## Verifying a release

Every release is built by GitHub Actions from a tagged commit, and ships with:

- `checksums.txt`, signed keylessly with [Sigstore](https://www.sigstore.dev/) (`checksums.txt.sigstore.json`);
- a [SLSA build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) for every archive;
- a CycloneDX SBOM for every archive (`*.sbom.json`).

To verify a download (replace the file name):

```sh
# 1. The checksums file was signed by this repository's release workflow
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/r-morato/tfcap/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Your archive matches the signed checksum
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt

# 3. The archive was built by this repository's workflow (needs the GitHub CLI)
gh attestation verify tfcap_<version>_linux_amd64.tar.gz -R r-morato/tfcap
```

The GitHub Action builds tfcap from its own source at the commit you pin, so pinning the Action to a SHA pins the scanner too.

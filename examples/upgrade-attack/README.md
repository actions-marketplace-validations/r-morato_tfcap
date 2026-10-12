# Upgrade-attack example

Two snapshots of the same root configuration after `terraform init`:

- `before/` uses `acme-oss/network/aws` **1.4.0**, a plain VPC module.
- `after/` uses **1.4.1**, a "patch release" that adds plan-time credential theft, a typosquatted provider and an admin backdoor role.

Everything here is **inert**. All endpoints use the reserved `.invalid` TLD (RFC 2606), which never resolves. The `.terraform/modules` folders are committed on purpose so you can run tfcap without network access:

```sh
tfcap scan  examples/upgrade-attack/before        # clean
tfcap scan  examples/upgrade-attack/after
tfcap diff  examples/upgrade-attack/before examples/upgrade-attack/after
```

Try `lock`/`verify` too: copy `before/` somewhere, run `tfcap lock`, then edit a file under `.terraform/modules/network/` and run `tfcap verify`.

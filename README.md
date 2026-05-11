# ksops

A SOPS companion CLI for editing, validating, and rekeying Kubernetes secrets.

`ksops` does not replace SOPS. It uses the `sops` binary for encryption, decryption,
editing, and key updates, while adding small GitOps-oriented workflows around it.

## Why ksops?

`sops` is excellent at encrypting files with age, GPG, KMS, and cloud key services.
But Kubernetes secret repos often need repeatable project workflows around that core.

`ksops` is a DX layer on top of `sops` for Kubernetes/GitOps repositories:

| | sops | ksops |
|---|---|---|
| Encrypt files for GitOps | ✅ | ✅ (via sops) |
| Edit encrypted files | ✅ | ✅ `ksops edit` |
| Decrypt to stdout | ✅ | ✅ `ksops cat` |
| Initialize Kubernetes Secret defaults | ❌ | ✅ `ksops init` |
| Encrypt all plaintext Secret manifests | ❌ | ✅ `ksops encrypt-all` |
| Rekey one file from `.sops.yaml` | ✅ `sops updatekeys` | ✅ `ksops rekey` |
| Rekey all encrypted manifests | ❌ | ✅ `ksops rekey-all` |
| Check plaintext Kubernetes Secret leaks | ❌ | ✅ `ksops validate-all` |

## Commands

```bash
ksops init
ksops edit secret.yaml
ksops cat secret.yaml
ksops encrypt secret.yaml --in-place
ksops encrypt-all ./manifests
ksops decrypt secret.yaml
ksops rekey secret.yaml
ksops rekey-all ./manifests
ksops validate-all ./manifests
ksops completion zsh
```

## Configuration

Encryption policy stays in native `.sops.yaml`.

```yaml
creation_rules:
  - path_regex: .*secret.*\.ya?ml$
    encrypted_regex: ^(data|stringData)$
    age: age1...
```

`ksops init` can create a starter `.sops.yaml`, but all encryption behavior is still
handled by SOPS itself.

## Shell Completion

```bash
source <(ksops completion bash)
source <(ksops completion zsh)
```

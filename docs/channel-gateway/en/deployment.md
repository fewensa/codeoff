# Deployment

Purpose: document the current container runtime shape.
Read this when building or running Codeoff outside the development workspace.
This does not define Kubernetes manifests or production secret management.

## Docker Image

The root `Dockerfile` builds Codeoff in a Rust builder stage and copies the release binary into a Debian-based Node runtime image. The runtime image installs Codex and common operational tools.

Included runtime tools include:

```text
codeoff
codex
rg
fd
bat
kubectl
helm
helmfile
kustomize
argocd
kubeseal
gh
just
jq
yq
git
git-lfs
python3
```

## Build

```bash
docker build -t codeoff:local .
```

## Runtime Inputs

Mount or provide:

- `/etc/codeoff/codeoff.toml`.
- `CODEOFF_STATE_DIR` or a persistent state volume.
- Slack tokens through environment variables or a secret manager.
- Codex configuration and credentials required by the local Codex installation.

The image default command is equivalent to:

```bash
codeoff --config /etc/codeoff/codeoff.toml --state-dir /var/lib/codeoff serve
```

For local non-container runs, use:

```bash
codeoff serve
```

Use the same config and state-dir flags with `serve --check` for deployment smoke tests.

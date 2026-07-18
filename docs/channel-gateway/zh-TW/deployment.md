# Deployment

目的：記錄目前 container runtime shape。
閱讀時機：在 development workspace 外 build 或 run Codeoff 前。
不涵蓋：Kubernetes manifests 或 production secret management。

## Docker Image

Root `Dockerfile` 在 Rust builder stage 編譯 Codeoff，並把 release binary 複製到 Debian-based Node runtime image。Runtime image 會安裝 Codex 與常用 operational tools。

Runtime tools 包含：

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

需要 mount 或提供：

- `/etc/codeoff/codeoff.toml`。
- `CODEOFF_STATE_DIR` 或 persistent state volume。
- 透過 environment variables 或 secret manager 提供 Slack tokens。
- 本機 Codex 所需的 config 與 credentials。

Image default command 等同於：

```bash
codeoff --config /etc/codeoff/codeoff.toml --state-dir /var/lib/codeoff serve
```

本機非 container 執行可使用：

```bash
codeoff serve
```

Deployment smoke test 使用同一組 config/state-dir flags 搭配：

```bash
codeoff --config /etc/codeoff/codeoff.toml --state-dir /var/lib/codeoff serve --check
```

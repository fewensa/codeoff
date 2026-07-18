# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.94.0
ARG DEBIAN_VERSION=bookworm

FROM rust:${DEBIAN_VERSION} AS builder

ARG RUST_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

WORKDIR /workspace/codeoff

COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates ./crates

RUN cargo build --release --locked -p codeoff-cli

FROM node:22-${DEBIAN_VERSION}-slim AS runtime

ARG CODEX_VERSION=latest
ARG TARGETARCH

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV CODEOFF_CONFIG=/etc/codeoff/codeoff.toml \
  CODEOFF_STATE_DIR=/var/lib/codeoff \
  CODEX_HOME=/var/lib/codex

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    apt-transport-https \
    bash \
    bat \
    build-essential \
    ca-certificates \
    curl \
    dnsutils \
    fd-find \
    git \
    git-lfs \
    gnupg \
    htop \
    iproute2 \
    jq \
    less \
    libssl-dev \
    make \
    nano \
    netcat-openbsd \
    neovim \
    openssh-client \
    pkg-config \
    procps \
    psmisc \
    python3 \
    python3-pip \
    python3-venv \
    ripgrep \
    sqlite3 \
    tar \
    tmux \
    unzip \
    vim \
    wget \
    xz-utils \
    zip \
  && npm install -g @openai/codex@${CODEX_VERSION} \
  && git lfs install --system \
  && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
  && ln -sf /usr/bin/batcat /usr/local/bin/bat \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /root/.npm

RUN set -eux; \
  case "${TARGETARCH:-amd64}" in \
    amd64) tool_arch=amd64; rust_arch=x86_64 ;; \
    arm64) tool_arch=arm64; rust_arch=aarch64 ;; \
    *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  kubectl_version="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"; \
  curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${kubectl_version}/bin/linux/${tool_arch}/kubectl"; \
  chmod +x /usr/local/bin/kubectl; \
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash; \
  curl -fsSL https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh | bash -s -- /usr/local/bin; \
  helmfile_url="$(curl -fsSL https://api.github.com/repos/helmfile/helmfile/releases/latest | jq -r --arg arch "${tool_arch}" '.assets[] | select(.name | test("^helmfile_.*_linux_" + $arch + "\\.tar\\.gz$")) | .browser_download_url' | head -n 1)"; \
  curl -fsSLo /tmp/helmfile.tar.gz "${helmfile_url}"; \
  tar -xzf /tmp/helmfile.tar.gz -C /tmp helmfile; \
  install -m 0755 /tmp/helmfile /usr/local/bin/helmfile; \
  rm -rf /tmp/helmfile /tmp/helmfile.tar.gz; \
  curl -fsSLo /usr/local/bin/argocd "https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-${tool_arch}"; \
  chmod +x /usr/local/bin/argocd; \
  kubeseal_url="$(curl -fsSL https://api.github.com/repos/bitnami-labs/sealed-secrets/releases/latest | jq -r --arg arch "${tool_arch}" '.assets[] | select(.name | test("^kubeseal-.*-linux-" + $arch + "\\.tar\\.gz$")) | .browser_download_url' | head -n 1)"; \
  curl -fsSLo /tmp/kubeseal.tar.gz "${kubeseal_url}"; \
  tar -xzf /tmp/kubeseal.tar.gz -C /tmp kubeseal; \
  install -m 0755 /tmp/kubeseal /usr/local/bin/kubeseal; \
  rm -rf /tmp/kubeseal /tmp/kubeseal.tar.gz; \
  gh_url="$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | jq -r --arg arch "${tool_arch}" '.assets[] | select(.name | test("^gh_.*_linux_" + $arch + "\\.tar\\.gz$")) | .browser_download_url' | head -n 1)"; \
  curl -fsSLo /tmp/gh.tar.gz "${gh_url}"; \
  mkdir -p /tmp/gh; \
  tar -xzf /tmp/gh.tar.gz -C /tmp/gh --strip-components=1; \
  install -m 0755 /tmp/gh/bin/gh /usr/local/bin/gh; \
  rm -rf /tmp/gh /tmp/gh.tar.gz; \
  curl -fsSLo /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${tool_arch}"; \
  chmod +x /usr/local/bin/yq; \
  just_url="$(curl -fsSL https://api.github.com/repos/casey/just/releases/latest | jq -r --arg arch "${rust_arch}" '.assets[] | select(.name | test("^just-.*-" + $arch + "-unknown-linux-musl\\.tar\\.gz$")) | .browser_download_url' | head -n 1)"; \
  curl -fsSLo /tmp/just.tar.gz "${just_url}"; \
  tar -xzf /tmp/just.tar.gz -C /tmp just; \
  install -m 0755 /tmp/just /usr/local/bin/just; \
  rm -rf /tmp/just /tmp/just.tar.gz

RUN groupadd --system codeoff \
  && useradd --system --gid codeoff --home-dir /var/lib/codeoff --create-home codeoff \
  && mkdir -p /etc/codeoff /var/lib/codeoff /var/lib/codex \
  && chown -R codeoff:codeoff /etc/codeoff /var/lib/codeoff /var/lib/codex

COPY --from=builder /workspace/codeoff/target/release/codeoff /usr/local/bin/codeoff

USER codeoff
WORKDIR /var/lib/codeoff

VOLUME ["/var/lib/codeoff", "/var/lib/codex"]

ENTRYPOINT ["codeoff"]
CMD ["--config", "/etc/codeoff/codeoff.toml", "--state-dir", "/var/lib/codeoff", "serve"]

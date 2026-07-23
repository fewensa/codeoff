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

ARG CODEX_VERSION=0.144.6
ARG CODEX_SCHEMA_SHA256=2bc9867446f03c818018ee33c249f4d1da22c3e19a68d606b0e435faba04f1d1
ARG CODEX_PROGRAM_SHA256=134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477
ARG GITHUB_MCP_VERSION=1.6.0
ARG TARGETARCH

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV CODEOFF_CONFIG=/etc/codeoff/codeoff.toml \
  CODEOFF_STATE_DIR=/var/lib/codeoff \
  CODEX_HOME=/var/lib/codex

RUN install -d -m 0755 /usr/local/libexec/codeoff

COPY --chmod=0644 scripts/codex-schema-hash.py /usr/local/libexec/codeoff/codex-schema-hash.py

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
  && mkdir -p /var/lib/codex \
  && test "${CODEX_VERSION}" = "0.144.6" \
  && npm install -g "@openai/codex@${CODEX_VERSION}" \
  && test "$(codex --version)" = "codex-cli ${CODEX_VERSION}" \
  && test "$(sha256sum /usr/local/lib/node_modules/@openai/codex/bin/codex.js | cut -d' ' -f1)" = "${CODEX_PROGRAM_SHA256}" \
  && codex_schema_dir="$(mktemp -d /tmp/codex-schema.XXXXXX)" \
  && codex app-server generate-json-schema --out "${codex_schema_dir}" \
  && actual_schema_sha256="$(python3 /usr/local/libexec/codeoff/codex-schema-hash.py "${codex_schema_dir}")" \
  && test "${actual_schema_sha256}" = "${CODEX_SCHEMA_SHA256}" \
  && codex_typescript_dir="$(mktemp -d /tmp/codex-typescript.XXXXXX)" \
  && codex app-server generate-ts --out "${codex_typescript_dir}" \
  && grep -Fq 'approvalPolicy?: AskForApproval | null' "${codex_typescript_dir}/v2/ThreadStartParams.ts" \
  && grep -Fq 'outputSchema?: JsonValue | null' "${codex_typescript_dir}/v2/TurnStartParams.ts" \
  && grep -Fq 'sandboxPolicy?: SandboxPolicy | null' "${codex_typescript_dir}/v2/TurnStartParams.ts" \
  && git lfs install --system \
  && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
  && ln -sf /usr/bin/batcat /usr/local/bin/bat \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /root/.npm

RUN set -eux; \
  test "${GITHUB_MCP_VERSION}" = "1.6.0"; \
  case "${TARGETARCH:-amd64}" in \
    amd64) github_mcp_arch=x86_64; github_mcp_archive_sha256=27443d173f209e60d4af9777e624bfea3de1af24897d46cc7324f01cf279a41d; github_mcp_binary_sha256=955fff9cf50ae99ee021871a4782c36360252d82fd03c8307fd7394c44ba3886 ;; \
    arm64) github_mcp_arch=arm64; github_mcp_archive_sha256=25f8028304202674ec2e9977fec3ca0897cac33866dabb51aefd418bc0ce7ef2; github_mcp_binary_sha256=5d47f9e36850769db8a46c97a7ad1e7a1bd51502c57765a81e697f5740455227 ;; \
    *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  github_mcp_archive=/tmp/github-mcp-server.tar.gz; \
  curl -fsSLo "${github_mcp_archive}" "https://github.com/github/github-mcp-server/releases/download/v${GITHUB_MCP_VERSION}/github-mcp-server_Linux_${github_mcp_arch}.tar.gz"; \
  printf '%s  %s\n' "${github_mcp_archive_sha256}" "${github_mcp_archive}" | sha256sum -c -; \
  tar -xzf "${github_mcp_archive}" -C /tmp github-mcp-server; \
  test "$(sha256sum /tmp/github-mcp-server | cut -d' ' -f1)" = "${github_mcp_binary_sha256}"; \
  install -m 0755 /tmp/github-mcp-server /usr/local/bin/github-mcp-server; \
  test "$(github-mcp-server --version | sed -n '2s/^Version: //p')" = "${GITHUB_MCP_VERSION}"; \
  github_mcp_inventory="$( \
    (printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"image-build-attestation","version":"1"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'; sleep 1) \
    | GITHUB_PERSONAL_ACCESS_TOKEN=non-secret-build-sentinel github-mcp-server stdio --read-only --tools=issue_read,list_issues,search_issues,search_orgs 2>/dev/null \
    | sed -n '2p' \
    | jq -r '[.result.tools[] | select(.annotations.readOnlyHint == true) | .name] | sort | join(",")' \
  )"; \
  test "${github_mcp_inventory}" = "issue_read,list_issues,search_issues,search_orgs"; \
  rm -f "${github_mcp_archive}" /tmp/github-mcp-server

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
  && install -d -o root -g root -m 0555 \
    /opt/codeoff/attestation \
    /opt/codeoff/scheduled-codex \
    /opt/codeoff/scheduled-workspace \
  && mkdir -p /etc/codeoff /var/lib/codeoff /var/lib/codex \
  && chown -R codeoff:codeoff /etc/codeoff /var/lib/codeoff /var/lib/codex

COPY --from=builder /workspace/codeoff/target/release/codeoff /usr/local/bin/codeoff

USER codeoff
WORKDIR /var/lib/codeoff

VOLUME ["/var/lib/codeoff", "/var/lib/codex"]

ENTRYPOINT ["codeoff"]
CMD ["--config", "/etc/codeoff/codeoff.toml", "--state-dir", "/var/lib/codeoff", "serve"]

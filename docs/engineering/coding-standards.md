# Coding Standards

Purpose: define project-wide coding, formatting, workspace, and test placement rules for Codeoff.
Read this before creating Rust crates, modules, tests, or shared project configuration.
This does not define product behavior, runtime architecture, or feature implementation order.

## Formatting

- Use spaces, not tabs.
- Use two spaces for indentation in Rust, TOML, Markdown, and project configuration files.
- Keep files UTF-8 encoded with LF line endings.
- Use `.editorconfig` as the editor-level source of truth.
- Use `rustfmt.toml` as the Rust formatting source of truth.
- Do not hand-format code in ways that fight `rustfmt`.

## Rust Toolchain

- Use `rust-toolchain.toml` to pin the project toolchain channel and required components.
- Required components:
  - `rustfmt`
  - `clippy`
- The workspace uses Rust edition 2024.

## Workspace

- Use the root `Cargo.toml` as the workspace manifest.
- Add crates to `[workspace].members` only when the crate directory and crate manifest exist.
- Keep workspace-level package metadata and lints in the root manifest.
- Do not manually edit generated lockfile content.

## Module Files

- `lib.rs` and `mod.rs` files are module wiring files only.
- Do not put business logic in `lib.rs` or `mod.rs`.
- Keep exports, module declarations, and small compatibility re-exports there.
- Put all real behavior in focused implementation files such as `config.rs`, `store.rs`, `adapter.rs`, `service.rs`, or domain-specific modules.

## File Size

- Keep each source file under 800 lines.
- If a file approaches the limit, split it by responsibility before adding more behavior.
- Prefer stable domain boundaries over generic utility buckets.

## Tests

- Keep test code outside `src`.
- Use crate-level `tests/` directories for integration and behavior tests.
- Do not add large `#[cfg(test)]` modules inside production source files.
- Small compile-time assertions may live near the code only when they are not behavior tests and materially improve readability.
- Test behavior, not implementation details.

## First Workspace Shape

The workspace should add crates only when they are needed by the current channel gateway implementation. Existing crates may remain while the product pivots, but new crates should support the daemon, channel connectors, Codex App Server dispatch, local MCP tools, state, CLI, or tests.

```text
crates/core
crates/config
crates/state
crates/channel/contract
crates/channel/slack
crates/runtime
crates/cli
crates/test-support
```

Each crate should place behavior tests in its own `tests/` directory.

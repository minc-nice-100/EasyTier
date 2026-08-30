# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

EasyTier is a decentralized, mesh P2P VPN written in Rust + Tokio. It is a Cargo workspace with three principal crates plus presentation/integration crates.

## Build / lint / test

Rust toolchain is pinned in `rust-toolchain.toml` (1.95, edition 2024). `protoc` 35.1 is required for `easytier-proto` codegen. The frontend (web/GUI) is built with pnpm.

The canonical verification path is CI via GitHub Actions (`.github/workflows/`). The repo's convention is to let CI verify rather than relying on local toolchains:

- Lint & check (`.github/workflows/test.yml` "check" job):
  ```bash
  cargo fmt --all -- --check
  cargo clippy --all-targets --features full --all -- -D warnings
  cargo hack check --package easytier --each-feature --exclude-features macos-ne --verbose
  cargo check --package easytier-core --lib --target wasm32-wasip1 \
    --features management-rpc,proxy-smoltcp-stack,ring-crypto,wasi-crypto-offload
  ```
- Tests: `cargo test --no-default-features --features=full --verbose` (uses `bridge-utils`; CI installs `miniupnpd` for NAT-related integration tests).
- `core.yml` builds release binaries across targets via `cargo build`/`cargo zigbuild` (Linux musl, macOS, Windows msvc, FreeBSD, MIPS with `build-std`).
- `gui.yml` / `mobile.yml` build the Tauri GUI and mobile apps.
- `release.yml` produces tagged releases.

Validation note for architecture changes (from `docs/core-architecture.md`):
```text
cargo fmt --all -- --check
cargo check -p easytier-core -p easytier-proto -p easytier --features full
cargo test -p easytier-core --lib
```

## Repository layout

- `easytier-core/` — portable control-plane core primitives. Compiles without direct OS network access; OS operations cross Host capability seams (Rust traits). WASI target adapter lives in `easytier-core/src/wasi`.
- `easytier-proto/` — generated protobuf messages and RPC types (`proto/*.proto`, `src/*.rs`). Split by features: `core`, `api`, `json-rpc`, `full`.
- `easytier/` — native composition root. Owns OS resources (TCP/UDP/DNS/TUN/routes/UPnP/NAT-PMP), CLI (`easytier-core`, `easytier-cli` binaries), service manager, web client. Crate name is `easytier`, and the lib is also `easytier`; binaries are `easytier-core` and `easytier-cli`.
- `easytier-web/` — web console. `easytier-web` binary exposes a REST API (`src/restful/`, default port 11211), a config server (`src/client_manager/`, default UDP 22020), webhook (`src/webhook.rs`), optional embedded frontend (`src/web/`, `embed` feature). SQLite DB via `src/db/`.
- `easytier-gui/` — Tauri desktop GUI (`easytier-gui/src-tauri`).
- `easytier-contrib/` — FFI, mini, uptime, Android JNI, iOS, Magisk, OHOS integrations.
- `docs/` — architecture and design docs. **`docs/core-architecture.md` is the source of truth for ownership, dependency direction, feature boundaries, and invariants.**

## Architecture (high level)

Crate dependency direction: `easytier-proto <- easytier-core <- easytier`.

Core internal layer order (downward): `foundation <- config/packet <- socket <- host <- tunnel <- listener/connectivity <- peers/rpc <- gateway <- instance <- management`.

Key concepts (detailed in `docs/core-architecture.md` and `CONTEXT.md`):

- **Module/Host/Adapter**: core implements portable policy behind Module interfaces. The Host process owns OS resources; an Adapter is a concrete Host-capability implementation.
- **Instance**: `CoreInstance::new(CoreInstanceConfig, CoreHostAdapters)` is the sole normalized construction path; one instance = one virtual network. `InstanceManager` is the canonical UUID-indexed collection.
- **Tunnel vs socket**: a socket is a raw endpoint; a Tunnel adds EasyTier framing/metadata/handshake. Transport tunnels live in `easytier-core/src/tunnel/` (tcp.rs, udp.rs, ring.rs, mpsc.rs, web_security.rs). Encryption primitives in `tunnel/encrypt/` and `tunnel/secure_datagram.rs`.
- **Connectivity**: `easytier-core/src/connectivity/` owns manual connect, STUN, NAT inference, UDP/TCP hole punching, and UDP port-mapping policy. Real UPnP/NAT-PMP calls belong to the native `easytier` crate Host side.
- **Management**: `easytier-core/src/management/` owns read-only instance/peer RPC and (with `management` feature) full process mutation, config transactions, persistence, logger control, and JSON-RPC presentation. RPC transport is in `easytier-core/src/rpc/` (peer-flavoured transport, fragmentation, client/server lifecycle, handler registry).
- **Runtime config authority**: `TomlConfig` is the authoritative desired config for readback/patch; the normalized core runtime store is authoritative for live behavior.
- **Features**: capabilities are coherent Cargo features, not source fragments. Default features: `aes-gcm`, `endpoint-discovery`, `extended-services`, `management`, `tcp-hole-punch`. `full` is the CI/test aggregate. Encrypted tunnels default to AES-GCM (WireGuard/Noise X25519 for WG tunnels); `chacha20`, `ring-crypto`, `openssl-crypto` are selectable engines.

## Coding conventions

- Modules are `pub(crate)` by default; each domain's `mod.rs` declares its outward surface.
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Unknown protobuf fields in reflected route info must survive forwarding/credential filtering (see OSPF wire editor `peers/route/route_peer_wire.rs`).
- New abstractions should pass a deletion test: deleting a useful deep Module should force non-trivial logic to reappear in multiple callers.

# AGENTS.md — `dfnet`

`dfnet` is a Linux forensic network triage, MAC management, read-only SMB/NFS share mounter, verified live-acquisition stream receiver (`dfnet stream` / `dfnet receive`), packet capture (`dfnet pcap`), temporary SSH (`dfnet ssh`), and Wi-Fi AP CLI/TUI in Rust (Ratatui + clap, MIT OR Apache-2.0).

## Multi-Repo & Dependency Context
- Part of the **df-suite** integrated into `~/git/dfnix`.
- Uses sibling Cargo path dependencies `../dfcore` (`~/git/dfcore`) and `../dflive/dfstream` (`~/git/dflive`). Keep local checkouts aligned with `flake.lock`.
- Push/release order on shared crate changes: `dfcore` -> `dflive` -> `dfnet` -> `dfnix`.

## Build & Verification
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
nix flake check   # includes NixOS VM/net checks: pcap, listen, ssh
```

## Forensic & Security Invariants (NEVER Break)
- **Atomic verified streams**: Write incoming streams to `*.incomplete` and rename ONLY after end record, byte count, and SHA-256 match. Refuse existing files/symlinks and non-empty or tmpfs destinations (unless `--allow-tmpfs`).
- **Authenticated pairing (`dfnet stream`)**: Preserve SPAKE2 + ChaCha20-Poly1305 guarantees and exit-code contract (0 complete, 4 empty, 5 hash mismatch, 6 incomplete, 7 zero-filled read errors).
- **Network isolation**: Share mounts must stay read-only; keep packet capture and temporary SSH scoped safely.
- **Tests**: Unit/CLI tests must not mutate live host network interfaces.

## Compact Instructions
When compacting, always preserve: `dfcore`/`dfstream` compatibility, protocol/exit-code contracts touched, `cargo test` / `nix flake check` outcomes, and open TODOs.

#!/usr/bin/env bash
# Run from WSL after syncing _wsl_sync → ~/vsbmas (see ../run_verify.sh).
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
cd ~/vsbmas
export RUST_LOG="${RUST_LOG:-info,backend=debug}"
echo "Building backend…"
cargo build -p backend -q
echo ""
echo "=== VSBMAS demo ==="
echo "Listening on 0.0.0.0:8080 (all interfaces)."
echo "In WSL:  http://localhost:8080/"
echo "From Windows browser: use http://localhost:8080/ if using default WSL port forwarding,"
echo "  or your WLAN IPv4 with portproxy (see scripts/setup_network.ps1)."
echo ""
exec cargo run -p backend --quiet

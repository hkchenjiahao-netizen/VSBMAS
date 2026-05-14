#!/usr/bin/env bash
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
DOC="/mnt/c/大学/新建文件夹/OneDrive - HKUST Connect/Desktop/Year 4/4000j/引导文档"
SYNC="/mnt/c/大学/新建文件夹/OneDrive - HKUST Connect/Desktop/Year 4/4000j/_wsl_sync"
cp -f "$SYNC/main.rs" ~/vsbmas/backend/src/main.rs
cp -f "$SYNC/backend_Cargo.toml" ~/vsbmas/backend/Cargo.toml
cp -f "$SYNC/l1.rs" ~/vsbmas/backend/src/l1.rs
cp -f "$SYNC/attack.rs" ~/vsbmas/backend/src/attack.rs
cp -f "$SYNC/state.rs" ~/vsbmas/backend/src/state.rs
cp -f "$SYNC/audit.rs" ~/vsbmas/backend/src/audit.rs
cp -f "$SYNC/blockchain.rs" ~/vsbmas/backend/src/blockchain.rs
cp -f "$SYNC/mining.rs" ~/vsbmas/backend/src/mining.rs
cp -f "$SYNC/house.rs" ~/vsbmas/crates/vsbmas_core/src/house.rs
cp -f "$SYNC/events.rs" ~/vsbmas/crates/vsbmas_core/src/events.rs
cp -f "$SYNC/serialize.rs" ~/vsbmas/crates/vsbmas_core/src/serialize.rs
cp -f "$SYNC/params.rs" ~/vsbmas/crates/vsbmas_core/src/params.rs
cp -f "$SYNC/lib.rs" ~/vsbmas/crates/vsbmas_core/src/lib.rs
cp -f "$SYNC/vsbmas_core_Cargo.toml" ~/vsbmas/crates/vsbmas_core/Cargo.toml
mkdir -p ~/vsbmas/crates/vsbmas_round/src
cp -f "$SYNC/vsbmas_round_lib.rs" ~/vsbmas/crates/vsbmas_round/src/lib.rs
cp -f "$SYNC/vsbmas_round_Cargo.toml" ~/vsbmas/crates/vsbmas_round/Cargo.toml
mkdir -p ~/vsbmas/web/assets
cp -f "$SYNC/web/"*.html ~/vsbmas/web/
cp -f "$SYNC/web/assets/"* ~/vsbmas/web/assets/
cd ~/vsbmas
cargo build -p backend -q
for n in "$@"; do
  echo "===== verify_${n} ====="
  bash "$DOC/verify/verify_${n}.sh"
done
#!/usr/bin/env bash
# VSBMAS v4 one-shot demo runner
#   - 杀掉旧 backend 进程
#   - 把 Windows 端 _wsl_sync/ 下的所有源码同步到 ~/vsbmas/
#   - release 构建
#   - 轮换 data/audit.jsonl（避免旧 boot 的 T=40 / mode=self 卡片污染前端）
#   - 打印关键参数横幅 & 可用 IP
#   - 前台运行 backend（VSBMAS_FRESH_AUDIT=1）
#
# 用法（在 WSL 里）：
#   bash "/mnt/c/大学/新建文件夹/OneDrive - HKUST Connect/Desktop/Year 4/4000j/_wsl_sync/run_demo.sh"
set -euo pipefail

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

SYNC="/mnt/c/大学/新建文件夹/OneDrive - HKUST Connect/Desktop/Year 4/4000j/_wsl_sync"
DEST="$HOME/vsbmas"

echo "==> [1/6] killing any stale backend processes…"
pkill -f "target/.*/backend" 2>/dev/null || true
pkill -f "cargo run -p backend" 2>/dev/null || true
sleep 0.5

echo "==> [2/6] syncing source trees from _wsl_sync → $DEST"
mkdir -p "$DEST/backend/src" \
         "$DEST/crates/vsbmas_core/src" \
         "$DEST/crates/vsbmas_round/src" \
         "$DEST/web/assets" \
         "$DEST/data"

# backend crate
cp -f "$SYNC/main.rs"              "$DEST/backend/src/main.rs"
cp -f "$SYNC/backend_Cargo.toml"   "$DEST/backend/Cargo.toml"
cp -f "$SYNC/l1.rs"                "$DEST/backend/src/l1.rs"
cp -f "$SYNC/attack.rs"            "$DEST/backend/src/attack.rs"
cp -f "$SYNC/state.rs"             "$DEST/backend/src/state.rs"
cp -f "$SYNC/audit.rs"             "$DEST/backend/src/audit.rs"
cp -f "$SYNC/blockchain.rs"        "$DEST/backend/src/blockchain.rs"
cp -f "$SYNC/mining.rs"           "$DEST/backend/src/mining.rs"

# vsbmas_core crate
cp -f "$SYNC/house.rs"              "$DEST/crates/vsbmas_core/src/house.rs"
cp -f "$SYNC/events.rs"             "$DEST/crates/vsbmas_core/src/events.rs"
cp -f "$SYNC/serialize.rs"          "$DEST/crates/vsbmas_core/src/serialize.rs"
cp -f "$SYNC/params.rs"             "$DEST/crates/vsbmas_core/src/params.rs"
cp -f "$SYNC/lib.rs"                "$DEST/crates/vsbmas_core/src/lib.rs"
cp -f "$SYNC/vsbmas_core_Cargo.toml" "$DEST/crates/vsbmas_core/Cargo.toml"

# vsbmas_round crate
cp -f "$SYNC/vsbmas_round_lib.rs"     "$DEST/crates/vsbmas_round/src/lib.rs"
cp -f "$SYNC/vsbmas_round_Cargo.toml" "$DEST/crates/vsbmas_round/Cargo.toml"

# web assets
cp -f "$SYNC/web/"*.html          "$DEST/web/"
cp -rf "$SYNC/web/assets/."       "$DEST/web/assets/"

echo "==> [3/6] release build (cargo build -p backend --release)"
cd "$DEST"
cargo build -p backend --release

echo "==> [4/6] rotating audit.jsonl"
AUDIT="$DEST/data/audit.jsonl"
if [ -f "$AUDIT" ]; then
  TS="$(date +%s)"
  mv "$AUDIT" "${AUDIT}.bak.${TS}"
  echo "    rotated → ${AUDIT}.bak.${TS}"
fi
: > "$AUDIT"

echo "==> [5/6] detecting LAN IP candidates"
IP_CANDIDATES="$(ip -4 addr show 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 || true)"
WIN_IP="$(powershell.exe -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {\$_.InterfaceAlias -match 'Wi-Fi|Ethernet' -and \$_.IPAddress -notlike '169.*'}).IPAddress" 2>/dev/null | tr -d '\r' | head -n1 || true)"

cat <<BANNER

================================================================
                VSBMAS · v4 classroom demo banner
================================================================
  MOD_BITS        = 2048
  TIME_PARAM (T)  = 16   →  2^T = 65536 sequential squarings
  DEMO_SQ_PER_SEC = 500  →  expected force-open ≈ 131 s (~2.2 min)
  NUM_BID_BITS    = 32

  ZK enforcement  : bid≥reserve & bid>prev_round_high via Bulletproofs
                    (verifier hard-reject, 400 zk_constraint_failed)

  audit log       : rotated per run via VSBMAS_FRESH_AUDIT=1
  boot_id         : generated on start; frontend filters via since_boot=true
----------------------------------------------------------------
  Listen on       : 0.0.0.0:8080 (bind inside backend — see backend/src/main.rs)

  LAN URLs :
BANNER
if [ -n "$WIN_IP" ]; then
  echo "    · http://$WIN_IP:8080/          (Windows host LAN — share this)"
fi
for ip in $IP_CANDIDATES; do
  echo "    · http://$ip:8080/          (from WSL)"
done
cat <<BANNER
----------------------------------------------------------------
  Pages           : /display.html   (classroom big screen)
                    /teacher.html   (teacher controls)
                    /student.html   (student self-service)
                    /blockchain.html (简易 PoW 链演示)
================================================================

BANNER

echo "==> [6/6] starting backend (VSBMAS_FRESH_AUDIT=1, foreground)…"
exec env VSBMAS_FRESH_AUDIT=1 cargo run -p backend --release

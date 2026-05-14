#!/usr/bin/env bash
set +e
cp ~/vsbmas/backend/src/attack.rs /tmp/attack.bak.rs
python3 - <<'PY'
import re, pathlib
p = pathlib.Path("/home/derri/vsbmas/backend/src/attack.rs")
src = p.read_text()
src = re.sub(r'^pub async fn (a[1-6]_\w+)', r'#[axum::debug_handler]\npub async fn \1', src, flags=re.M)
p.write_text(src)
PY
cd ~/vsbmas && cargo check -p backend 2>&1 | tee /tmp/dbg.log | head -200

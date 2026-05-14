#!/usr/bin/env bash
cd ~
for f in \
  vsbmas/backend/src/l1.rs \
  vsbmas/backend/Cargo.toml \
  vsbmas/backend/src/attack.rs \
  vsbmas/backend/src/main.rs \
  vsbmas/web/student.html \
  vsbmas/data/audit.jsonl \
  vsbmas/crates/vsbmas_core/src/house.rs \
  ; do
  if [ -f "$f" ]; then
    sz=$(stat -c %s "$f")
    sh=$(sha256sum "$f" | awk '{print $1}')
    echo "$f|$sh|$sz"
  else
    echo "$f|MISSING"
  fi
done

#!/usr/bin/env bash
echo "=== backend/Cargo.toml ==="
cat ~/vsbmas/backend/Cargo.toml
echo
echo "=== grep optional ==="
grep -nE "solidity|optional" ~/vsbmas/backend/Cargo.toml || true
echo
echo "=== grep '^\[features\]' ==="
grep -nE '^\[features\]' ~/vsbmas/backend/Cargo.toml || true

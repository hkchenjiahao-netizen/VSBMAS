#!/usr/bin/env bash
grep -n "debug_handler" ~/vsbmas/backend/src/attack.rs | head
echo "---"
grep -n "^pub async fn" ~/vsbmas/backend/src/attack.rs

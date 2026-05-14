#!/usr/bin/env bash
pat='solidity.*optional\|optional[[:space:]]*=[[:space:]]*true'
echo "Using grep -qE pattern: $pat"
grep -qE "$pat" ~/vsbmas/backend/Cargo.toml && echo MATCH || echo NOMATCH
echo "---"
grep -E "$pat" ~/vsbmas/backend/Cargo.toml || echo "no match"
echo "---"
pat2='solidity.*optional|optional[[:space:]]*=[[:space:]]*true'
echo "Using grep -qE pattern2: $pat2"
grep -qE "$pat2" ~/vsbmas/backend/Cargo.toml && echo MATCH2 || echo NOMATCH2

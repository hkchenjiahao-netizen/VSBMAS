#!/usr/bin/env bash
set +e
export CARGO_BUILD_JOBS=2
export MAKEFLAGS="-j2"
DOC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/引导文档"
for n in "$@"; do
  echo "===== verify_${n} ====="
  bash "$DOC/verify/verify_${n}.sh" > "/tmp/v_${n}.log" 2>&1
  ec=$?
  echo "EXIT_${n}=$ec"
  tail -30 "/tmp/v_${n}.log"
  if [ $ec -ne 0 ]; then
    echo "STOP at $n"
    exit $ec
  fi
done
echo "ALL_DONE"

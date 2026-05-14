#!/usr/bin/env bash
set -euo pipefail
. "$HOME/.cargo/env"
F="$HOME/vsbmas/data/audit.jsonl"
touch "$F"
before=$(wc -l < "$F")
DOC="/mnt/c/大学/新建文件夹/OneDrive - HKUST Connect/Desktop/Year 4/4000j/引导文档"
# shellcheck source=../引导文档/verify/_lib.sh
source "$DOC/verify/_lib.sh"
stop_backend || true
start_backend
sleep 1
a=$(curl_json POST /api/accounts '{"name":"alice","initial_balance":1000}' | jq -r .id)
b=$(curl_json POST /api/accounts '{"name":"bob","initial_balance":1000}' | jq -r .id)
auc=$(curl_json POST /api/auctions \
  '{"item_name":"E2E","total_duration_secs":300,"round_duration_secs":60,"reserve_price":10}' \
  | jq -r .id)
curl_json POST "/api/auctions/$auc/bid" "{\"user_id\":$a,\"amount\":150}" >/dev/null
curl_json POST "/api/auctions/$auc/bid" "{\"user_id\":$b,\"amount\":120}" >/dev/null
curl -fsS -X POST "${BACKEND_URL}/api/auctions/$auc/self_open" \
  -H 'content-type: application/json' \
  -d "{\"user_id\":$a,\"bid\":150}" || true
curl -fsS -X POST "${BACKEND_URL}/api/auctions/$auc/settle" \
  -H 'content-type: application/json' -d '{}' || true
sleep 1
after=$(wc -l < "$F")
delta=$((after - before))
echo "before=$before after=$after delta=$delta"
echo "types in tail:"
tail -n "$delta" "$F" | jq -r .type
echo "jq AccountCreated test:"
tail -n "$delta" "$F" | jq -e --arg t AccountCreated 'select(.type==$t)' >/dev/null && echo OK || echo FAIL
stop_backend || true

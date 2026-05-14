#!/bin/bash
printf '%s\n' '{"type":"AccountCreated"}' '{"type":"AccountCreated"}' | jq -e --arg t AccountCreated 'select(.type==$t)'
echo exit:$?
printf '%s\n' '{"type":"AccountCreated"}' '{"type":"SelfOpened"}' | jq -e --arg t AccountCreated 'select(.type==$t)' >/dev/null
echo exit2:$?

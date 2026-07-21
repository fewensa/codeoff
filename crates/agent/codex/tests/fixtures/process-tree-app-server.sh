#!/bin/sh
set -eu

sleep 300 &
grandchild_pid=$!
printf '%s\n' "${grandchild_pid}" > "${TEST_GRANDCHILD_PID_FILE}"

while IFS= read -r _line; do
  :
done

wait "${grandchild_pid}"

#!/bin/sh
set -eu

sh -c 'trap "" TERM; while :; do sleep 300; done' &
grandchild_pid=$!
printf '%s\n' "${grandchild_pid}" > grandchild.pid

# Deliberately exit the process-group leader before cleanup. The descendant keeps the App Server
# stdout open and ignores SIGTERM, so cleanup must prove the PGID is gone after SIGKILL.
exit 0

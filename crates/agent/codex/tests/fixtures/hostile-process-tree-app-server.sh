#!/bin/sh
set -eu

setsid sh -c 'trap "" TERM; while :; do sleep 300; done' &
printf '%s\n' "$!" > setsid.pid

sh -c 'setsid sh -c '\''trap "" TERM; while :; do sleep 300; done'\'' & printf "%s\n" "$!" > double-fork.pid'

setsid sh -c '
  trap "" TERM
  while :; do
    setsid sh -c '\''trap "" TERM; sleep 300'\'' &
    printf "%s\n" "$!" > fork-race.pid
    sleep 0.01
  done
' &
printf '%s\n' "$!" > fork-race-parent.pid

exit 0

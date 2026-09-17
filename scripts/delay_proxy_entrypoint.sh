#!/bin/sh
set -eu

: "${DELAY_MS:?DELAY_MS is required}"
: "${UPSTREAM_HOST:?UPSTREAM_HOST is required}"
: "${UPSTREAM_PORT:?UPSTREAM_PORT is required}"

case "$DELAY_MS" in
  ''|*[!0-9]*)
    echo "DELAY_MS must be a non-negative integer" >&2
    exit 2
    ;;
esac

# The proxy relays both halves of each TCP exchange. Every packet leaving the
# proxy, toward either the caller or upstream service, receives DELAY_MS.
tc qdisc replace dev eth0 root netem delay "${DELAY_MS}ms"

exec socat \
  TCP-LISTEN:8000,fork,reuseaddr,nodelay \
  "TCP:${UPSTREAM_HOST}:${UPSTREAM_PORT},nodelay"

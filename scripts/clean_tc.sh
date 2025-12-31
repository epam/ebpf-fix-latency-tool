#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then echo "usage: $0 <iface>"; exit 1; fi
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
echo "clsact detached from $IFACE"

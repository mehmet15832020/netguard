#!/bin/sh
set -e
IFACE="${ZEEK_INTERFACE:-vmnet8}"
LOGDIR="${ZEEK_LOG_DIR:-/zeek-logs}"
mkdir -p "$LOGDIR"
cd "$LOGDIR"
exec zeek -i "$IFACE" -C local

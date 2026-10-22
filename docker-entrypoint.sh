#!/bin/sh
# Starts the registry as the unprivileged brr user. The data directory is
# handed to that user first: a platform volume is usually owned by root.
# Nothing runs as root after that.
set -eu
data="${BRR_DATA_DIR:-/data}"
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$data"
  chown -R brr:brr "$data"
  chmod 700 "$data"
  exec su-exec brr /usr/local/bin/brr "$@"
fi
exec /usr/local/bin/brr "$@"

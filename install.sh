#!/bin/sh
# Run from a reviewed checkout. No curl|bash and no hardcoded repository URL.
set -eu
cd -- "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
if [ "$(id -u)" -ne 0 ]; then echo 'Run with sudo: sudo bash install.sh' >&2; exit 1; fi
if ! command -v python3 >/dev/null 2>&1; then
    sh ./scripts-bootstrap.sh python3
fi
exec python3 ./installer.py "$@"

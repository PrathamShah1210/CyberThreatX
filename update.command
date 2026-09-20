#!/bin/bash
set -e
cd -- "$(dirname -- "$0")"
git pull --ff-only origin main
export PORT="${PORT:-8003}"
exec bash start.command

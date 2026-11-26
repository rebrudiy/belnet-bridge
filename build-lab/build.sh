#!/usr/bin/env bash
set -euo pipefail

task_root=$(cd "$(dirname "$0")" && pwd)
exec bash "$task_root/fresh-build.sh" "$@"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npm run lint
npm --prefix sdk/typescript run build
npm test

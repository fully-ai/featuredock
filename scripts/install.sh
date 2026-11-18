#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npm install
npm --prefix sdk/typescript install
npm --prefix sdk/typescript run build
npm run build

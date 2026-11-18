$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
npm run lint
npm --prefix sdk/typescript run build
npm test

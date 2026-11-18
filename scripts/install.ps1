$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
npm install
npm --prefix sdk/typescript install
npm --prefix sdk/typescript run build
npm run build

# Security Policy

## Reporting a Vulnerability

Please report security issues responsibly via GitHub Security Advisories without publishing exploit vectors prior to a fix.

## Security Model

1. **Separated Control-Plane vs SDK Keys:** Management mutations require RBAC-authenticated users (`admin`, `editor`, `viewer`) or `fd_adm_` API tokens, while `fd_sdk_` keys are scoped strictly to evaluating flags and posting telemetry within one environment.
2. **Cryptographic Storage:** Passwords use salted `scrypt`; API tokens and SDK keys are hashed (`SHA-256`) or scoped; sessions use HMAC-SHA256 JWTs.
3. **ReDoS Guard on Regex Rules:** Custom `regex` targeting rules enforce length bounds and safe compilation.

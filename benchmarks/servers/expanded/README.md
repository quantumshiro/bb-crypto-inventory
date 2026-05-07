# Expanded Benchmark Servers

These intentionally vulnerable services broaden BBCI's practical benchmark coverage beyond the default Python fixture.

- `go_vuln` exposes `/api/decrypt` on port `8081` and leaks padding-specific error messages.
- `rust_vuln` exposes `/api/verify` on port `8082` and uses a deliberately non-constant-time HMAC comparison.
- `node_vuln` exposes `/api/auth` on port `8083` and accepts JWTs with `alg=none`.

The services are for local benchmark and scanner validation only. Do not deploy them on public networks.

# Proposed publication

This archive is the tree proposed for a public repository, assembled for review.
It is not a git history and it is not the application-builder workspace it was developed in.

## Included

- Rust sidecar: `proxy/src`, `proxy/Cargo.toml`, `proxy/Cargo.lock`, `proxy/Dockerfile`
- Go comparison port: `proxy/*.go` (not the container image)
- Deployment: `deploy/` (nftables, Istio injection, Vector, VictoriaLogs)
- Dashboard sources that implement the Tapline UI: `src/components/tapline`, `src/lib/proxy`, `src/routes/index.tsx`, `src/lib/utils.ts`, and the UI primitives those files import
- `README.md`, `LICENSE` (Apache License 2.0)

## Not included

The surrounding workspace is an application-builder scaffold and is not proposed for publication:

- `AGENTS.md`, `public/__grok/`, `scripts/grok-*`, `server/middleware/grok-pwa.ts`
- authentication, preview-bridge, and multiplayer helpers under `src/lib/auth` and `src/lib/preview-*`
- `node_modules/`, `proxy/target/`, and `screenshots/`

The dashboard files are here so they can be read. They are not a standalone application; they expect a TanStack Start shell, which is not in this archive.

Earlier throughput numbers were removed. They were taken before DLP, UDP, and MCP were added, and they are not reproducible from this tree.

## License notice in the tree

`LICENSE` and `README.md` use the copyright line "Copyright 2026 The Tapline Authors".

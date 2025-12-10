# Folder Structure Plan

Agreed layout for the new Go-based implementation of the IPv6 test tools:

- `cmd/testipv6/` — CLI entrypoint; invokes `pkg/ipv6test` to run checks locally and emit text/JSON.
- `cmd/testipv6-server/` — HTTP server entrypoint; serves APIs for the web UI and can serve embedded static assets.
- `web/` — Front-end source (Vue/React) and build artifacts. Keep source under `web/src/`; place the built bundle in `web/dist/`.
- `pkg/ipv6test/` — Core test logic (IPv4/IPv6/dual-stack/MTU/DNS/ASN probing) shared by CLI and server.
- Optional supporting packages under `pkg/`:
  - `pkg/netprobe/` — low-level HTTP/DNS/MTU probing helpers.
  - `pkg/config/` — configuration loading and defaults.
  - `pkg/api/` — HTTP handlers and response shapes, if you want to keep server glue reusable.
- `api/openapi.yaml` — OpenAPI/Swagger definition for the server APIs; can be embedded by `testipv6-server` and served (e.g., `/swagger/openapi.yaml`) or used for client generation.

Embedding the front-end:
- Build the UI to `web/dist/`, then use `//go:embed web/dist/*` in the server to serve static files via `http.FileServer` (add SPA fallback to `index.html` if needed).
- Expose APIs under `/api/*`; serve static assets from `/`.

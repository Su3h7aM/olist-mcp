# Olist ERP MCP

Work in progress: a Go MCP server and local multi-account mirror for Olist ERP. The server, authentication, and synchronization are not implemented yet.

The reconciled design is in `ARCHITECTURE-v2.1-reconciled.md` and the multi-account updates are in `ARCHITECTURE-v2.3-multiaccount-schema.md`. `openapi.json` is the Olist ERP v3 OpenAPI specification used for design.

The initial mirror schema is in `migrations/001_mirror.sql`. Its preliminary SQLite checks can be run with `python3 -m unittest discover -s tests -v`. These checks do not replace validation with the Go SQLite driver.

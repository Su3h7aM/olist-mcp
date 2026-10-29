# Project guidelines

- Use Conventional Commits with a type, scope, and concise description, for example `feat(sync): resume interrupted backfill`.
- Preserve account isolation: identify remote records by account and remote ID, and enforce authorization on every operation.
- Keep credentials and runtime databases out of version control. Never log secrets.
- Follow the reconciled architecture and explicitly document deviations and limitations.
- Keep the server pure Go with CGO disabled; test behavior and security boundaries for changes.
- Avoid automatic identity merges when identifiers are missing or ambiguous.

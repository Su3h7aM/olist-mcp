package migrations

import _ "embed"

//go:embed 001_mirror.sql
var Initial string

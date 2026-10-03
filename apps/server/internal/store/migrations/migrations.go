// Package migrations embeds the SQL migration files.
package migrations

import "embed"

// FS contains all *.up.sql / *.down.sql migrations under sql/.
//
//go:embed sql
var FS embed.FS

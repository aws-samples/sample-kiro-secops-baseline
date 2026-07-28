// Package assets embeds the payload (DevSecOps baseline) into the binary via //go:embed.
// The payload must live here (next to this file) because //go:embed cannot
// see parent directories.
package assets

import "embed"

//go:embed all:payload
var FS embed.FS

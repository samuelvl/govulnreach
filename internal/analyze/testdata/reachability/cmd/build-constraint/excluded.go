//go:build govulnreach_excluded

package main

import "github.com/go-openapi/swag/jsonutils"

func excluded() { _, _ = jsonutils.WriteJSON(nil) }

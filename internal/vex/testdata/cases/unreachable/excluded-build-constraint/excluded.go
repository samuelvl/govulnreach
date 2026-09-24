//go:build govulnreach_excluded

package main

import "example.com/vulnerable/parser"

func excluded() { _, _ = jsonutils.WriteJSON(nil) }

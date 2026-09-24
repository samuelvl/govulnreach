package main

import "github.com/go-openapi/swag/jsonutils"

func dead() { _, _ = jsonutils.WriteJSON(nil) }

func main() { _ = jsonutils.ConcatJSON(nil) }

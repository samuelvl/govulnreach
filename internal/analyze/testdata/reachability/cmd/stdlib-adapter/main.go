package main

import adapter "github.com/go-openapi/swag/jsonutils/adapters/stdlib/json"

func main() { _, _ = adapter.Adapter{}.OrderedMarshal(nil) }

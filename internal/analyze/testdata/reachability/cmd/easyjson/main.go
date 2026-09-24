package main

import adapter "github.com/go-openapi/swag/jsonutils/adapters/easyjson/json"

func main() { _ = adapter.MapItem{}.MarshalEasyJSON() }

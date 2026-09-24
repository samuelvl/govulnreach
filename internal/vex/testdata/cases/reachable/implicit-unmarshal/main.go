package main

import (
	"encoding/json"

	"example.com/vulnerable/parser"
)

func main() {
	var value jsonutils.JSONMapSlice
	_ = json.Unmarshal([]byte(`[]`), &value)
}

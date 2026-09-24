package main

import (
	"encoding/json"

	"example.com/vulnerable/parser"
)

func main() { _, _ = json.Marshal(jsonutils.JSONMapSlice{}) }

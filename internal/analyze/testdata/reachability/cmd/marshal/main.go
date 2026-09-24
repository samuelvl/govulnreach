package main

import (
	"encoding/json"

	"github.com/go-openapi/swag/jsonutils"
)

func main() { _, _ = json.Marshal(jsonutils.JSONMapSlice{}) }

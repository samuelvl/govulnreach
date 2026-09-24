package main

import (
	"encoding/json"

	"github.com/go-openapi/swag/jsonutils"
)

func main() {
	var value jsonutils.JSONMapSlice
	_ = json.Unmarshal([]byte(`[]`), &value)
}

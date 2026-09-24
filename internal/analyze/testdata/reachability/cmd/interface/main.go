package main

import (
	"example.com/reachability/interfacehelper"
	"github.com/go-openapi/swag/jsonutils"
)

func main() { interfacehelper.Marshal(jsonutils.JSONMapSlice{}) }

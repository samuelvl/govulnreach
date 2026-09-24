package main

import (
	"example.com/reachability/callbackstore"
	"github.com/go-openapi/swag/jsonutils"
)

var writeJSON = func() { _, _ = jsonutils.WriteJSON(nil) }

func newCallback() func() { return func() { writeJSON() } }

func main() {
	command := &callbackstore.Command{Run: newCallback()}
	command.Execute()
}

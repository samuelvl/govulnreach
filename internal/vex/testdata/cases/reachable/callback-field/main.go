package main

import (
	"example.com/cases/callbackstore"
	"example.com/vulnerable/parser"
)

var writeJSON = func() { _, _ = jsonutils.WriteJSON(nil) }

func newCallback() func() { return func() { writeJSON() } }

func main() {
	command := &callbackstore.Command{Run: newCallback()}
	command.Execute()
}

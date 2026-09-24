package main

import (
	"example.com/cases/callbackhelper"
	"example.com/vulnerable/parser"
)

func main() {
	callbackhelper.Run(func() { _, _ = jsonutils.WriteJSON(nil) })
}

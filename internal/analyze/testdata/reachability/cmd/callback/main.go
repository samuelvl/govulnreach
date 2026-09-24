package main

import (
	"example.com/reachability/callbackhelper"
	"github.com/go-openapi/swag/jsonutils"
)

func main() {
	callbackhelper.Run(func() { _, _ = jsonutils.WriteJSON(nil) })
}

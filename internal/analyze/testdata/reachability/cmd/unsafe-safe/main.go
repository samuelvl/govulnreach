package main

import (
	"unsafe"

	"github.com/go-openapi/swag/jsonutils"
)

func main() {
	value := 1
	_ = unsafe.Pointer(&value)
	_ = jsonutils.ConcatJSON(nil)
}

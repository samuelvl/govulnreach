package main

import (
	"unsafe"

	"github.com/go-openapi/swag/jsonutils"
)

func main() {
	value := jsonutils.JSONMapSlice{}
	_ = unsafe.Pointer(&value)
	_ = jsonutils.ConcatJSON(nil)
}

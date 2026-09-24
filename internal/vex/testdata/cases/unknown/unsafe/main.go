package main

import (
	"unsafe"

	"example.com/vulnerable/parser"
)

func main() {
	value := jsonutils.JSONMapSlice{}
	_ = unsafe.Pointer(&value)
	_ = jsonutils.ConcatJSON(nil)
}

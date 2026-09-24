package main

import (
	"unsafe"

	"example.com/vulnerable/parser"
)

func main() {
	value := 1
	_ = unsafe.Pointer(&value)
	_ = jsonutils.ConcatJSON(nil)
}

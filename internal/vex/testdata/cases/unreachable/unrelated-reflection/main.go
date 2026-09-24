package main

import (
	"reflect"

	"example.com/vulnerable/parser"
)

func main() {
	_ = reflect.TypeOf(1)
	_ = jsonutils.ConcatJSON(nil)
}

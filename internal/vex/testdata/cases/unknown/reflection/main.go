package main

import (
	"reflect"

	"example.com/vulnerable/parser"
)

func main() {
	reflect.ValueOf(jsonutils.WriteJSON).Call([]reflect.Value{reflect.Zero(reflect.TypeFor[any]())})
}

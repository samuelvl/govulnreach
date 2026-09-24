package main

import (
	"reflect"

	"github.com/go-openapi/swag/jsonutils"
)

func main() {
	reflect.ValueOf(jsonutils.WriteJSON).Call([]reflect.Value{reflect.Zero(reflect.TypeFor[any]())})
}

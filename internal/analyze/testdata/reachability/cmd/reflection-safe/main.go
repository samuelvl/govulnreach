package main

import (
	"reflect"

	"github.com/go-openapi/swag/jsonutils"
)

func main() {
	_ = reflect.TypeOf(1)
	_ = jsonutils.ConcatJSON(nil)
}

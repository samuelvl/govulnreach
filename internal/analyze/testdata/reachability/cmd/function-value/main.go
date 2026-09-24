package main

import "github.com/go-openapi/swag/jsonutils"

func main() {
	write := jsonutils.WriteJSON
	_, _ = write(nil)
}

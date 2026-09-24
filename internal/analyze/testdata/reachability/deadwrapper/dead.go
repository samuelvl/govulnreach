package deadwrapper

import "github.com/go-openapi/swag/jsonutils"

func Safe() {}

func Vulnerable() {
	_, _ = jsonutils.WriteJSON(nil)
}

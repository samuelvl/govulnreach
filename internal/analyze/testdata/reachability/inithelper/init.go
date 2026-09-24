package inithelper

import "github.com/go-openapi/swag/jsonutils"

func init() { _, _ = jsonutils.WriteJSON(nil) }

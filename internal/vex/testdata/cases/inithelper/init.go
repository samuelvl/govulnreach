package inithelper

import "example.com/vulnerable/parser"

func init() { _, _ = jsonutils.WriteJSON(nil) }

package wrapper

import "example.com/vulnerable/parser"

func Write() { _, _ = jsonutils.WriteJSON(nil) }

package deadwrapper

import "example.com/vulnerable/parser"

func Safe() {}

func Vulnerable() {
	_, _ = jsonutils.WriteJSON(nil)
}

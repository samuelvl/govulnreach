package main

import "example.com/vulnerable/parser"

func main() { _ = jsonutils.ConcatJSON([]byte(`{}`)) }

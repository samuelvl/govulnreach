package main

import "example.com/vulnerable/parser"

func dead() { _, _ = jsonutils.WriteJSON(nil) }

func main() { _ = jsonutils.ConcatJSON(nil) }

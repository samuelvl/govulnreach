package main

import "example.com/vulnerable/parser"

func main() { _, _ = jsonutils.WriteJSON(nil) }

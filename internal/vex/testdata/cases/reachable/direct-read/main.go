package main

import "example.com/vulnerable/parser"

func main() { _ = jsonutils.ReadJSON(nil, nil) }

package main

import (
	"example.com/cases/interfacehelper"
	"example.com/vulnerable/parser"
)

func main() { interfacehelper.Marshal(jsonutils.JSONMapSlice{}) }

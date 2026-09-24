package main

import (
	"testing"

	"example.com/vulnerable/parser"
)

func TestWrite(t *testing.T) { _, _ = jsonutils.WriteJSON(nil) }

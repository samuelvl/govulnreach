package main

import (
	"testing"

	"github.com/go-openapi/swag/jsonutils"
)

func TestWrite(t *testing.T) { _, _ = jsonutils.WriteJSON(nil) }

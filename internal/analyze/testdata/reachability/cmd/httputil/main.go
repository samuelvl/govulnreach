package main

import (
	"net/http"
	"net/http/httputil"
)

func main() {
	_, _ = httputil.DumpRequest(&http.Request{}, false)
}

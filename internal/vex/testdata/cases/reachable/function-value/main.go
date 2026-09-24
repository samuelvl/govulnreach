package main

import "example.com/vulnerable/parser"

func main() {
	write := jsonutils.WriteJSON
	_, _ = write(nil)
}

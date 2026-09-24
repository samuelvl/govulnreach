package main

import adapter "example.com/vulnerable/easyjson"

func main() { _ = adapter.MapItem{}.MarshalEasyJSON() }

package main

import adapter "example.com/vulnerable/stdlib"

func main() { _, _ = adapter.Adapter{}.OrderedMarshal(nil) }

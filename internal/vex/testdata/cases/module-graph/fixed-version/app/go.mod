module example.com/fixed

go 1.26.8

require example.com/vulnerable v0.2.0

replace example.com/vulnerable => ../../../../modules/vulnerable

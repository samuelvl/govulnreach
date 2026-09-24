module example.com/reachability

go 1.26.8

require (
	github.com/go-openapi/swag/jsonutils v0.25.5
	github.com/go-openapi/swag/jsonutils/adapters/easyjson v0.25.5
)

replace github.com/go-openapi/swag/jsonutils => ../modules/jsonutils

replace github.com/go-openapi/swag/jsonutils/adapters/easyjson => ../modules/easyjson

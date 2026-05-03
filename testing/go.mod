module github.com/quic-go/go-ossfuzz-seeds/testing

go 1.25.0

require (
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20250911191804-fc5dc53b9db8
	github.com/quic-go/go-ossfuzz-seeds v0.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/quic-go/go-ossfuzz-seeds => ../

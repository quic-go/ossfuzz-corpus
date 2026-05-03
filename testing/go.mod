module github.com/quic-go/ossfuzz-corpus/testing

go 1.25.0

require (
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20250911191804-fc5dc53b9db8
	github.com/quic-go/ossfuzz-corpus v0.0.0
)

replace github.com/quic-go/ossfuzz-corpus => ../

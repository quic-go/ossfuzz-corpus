# go-ossfuzz-seeds

[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/go-ossfuzz-seeds)](https://pkg.go.dev/github.com/quic-go/go-ossfuzz-seeds)


Go fuzz tests commonly add seeds with `testing.F.Add`, but OSS-Fuzz's native fuzz build [ignores](https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/) them. The result is that an OSS-Fuzz target starts from an empty corpus.

This package bridges that gap. It wraps `*testing.F` and keeps normal Go fuzzing behavior unchanged, while optionally writing each `Add` seed in the raw corpus format consumed by OSS-Fuzz's Go fuzzing helper.


## Usage

Wrap `*testing.F` and use the wrapper for calls to `Add`:

```go
package mypackage

import (
	"testing"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"
)

func FuzzParse(f *testing.F) {
	corpus := ossfuzzseeds.New(f)

	corpus.Add(uint8(1), "GET", []byte("/index.html"))
	corpus.Add(uint8(2), "POST", []byte("/api/v1/resource"))

	f.Fuzz(func(t *testing.T, version uint8, method string, path []byte) {
		// fuzz target
	})
}
```

When `FUZZ_CORPUS_DIR` is unset, `corpus.Add` behaves like `f.Add`. 
When `FUZZ_CORPUS_DIR` is set, it also writes one OSS-Fuzz-compatible corpus file per seed.

In an OSS-Fuzz or ClusterFuzz build script, run the fuzzer once with `FUZZ_CORPUS_DIR` set, then package the generated files as
`<fuzzer>_seed_corpus.zip` in `$OUT`:

```bash
corpus_dir="$WORK/my_fuzzer_seed_corpus"
mkdir -p "$corpus_dir"

FUZZ_CORPUS_DIR="$corpus_dir" go test ./mypackage -run '^FuzzParse$' -count=1

(cd "$corpus_dir" && zip -q -r "$OUT/my_fuzzer_seed_corpus.zip" .)
compile_native_go_fuzzer_v2 github.com/me/project/mypackage FuzzParse my_fuzzer
```


## Testing

The compatibility tests live in `testing`, a nested Go module, so this module does not need to include any dependencies on `go-118-fuzz-build` at runtime.

The encoding is tested against [`github.com/AdamKorcz/go-118-fuzz-build/input.Source`](https://github.com/AdamKorcz/go-118-fuzz-build/blob/fc5dc53b9db8a38c394c53d6e439a1410cf8fc19/input/reader.go#L167-L209), which is the helper used by [`compile_native_go_fuzzer_v2`](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_native_go_fuzzer_v2).

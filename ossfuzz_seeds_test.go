package ossfuzzseeds_test

import (
	"os"
	"os/exec"
	"testing"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"

	"github.com/stretchr/testify/require"
)

var mixedSeeds = [][]any{
	{uint8(1), "GET", []byte("/index.html")},
	{uint8(2), "POST", []byte("/api/v1/resource")},
}

var fixedSeeds = [][]any{
	{true, uint32(42), float64(1.5)},
	{false, uint32(0xdeadbeef), float64(-123.25)},
}

func TestHelperWritesCorpusFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fuzz  string
		seeds [][]any
	}{
		{name: "mixed arguments", fuzz: "FuzzMixedSeedCorpus", seeds: mixedSeeds},
		{name: "fixed arguments", fuzz: "FuzzFixedSeedCorpus", seeds: fixedSeeds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corpusDir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^"+tc.fuzz+"$")
			cmd.Env = append(os.Environ(), "FUZZ_CORPUS_DIR="+corpusDir)

			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s failed:\n%s", tc.fuzz, output)

			assertCorpusFiles(t, corpusDir, tc.seeds)
		})
	}
}

func FuzzMixedSeedCorpus(f *testing.F) {
	corpus := ossfuzzseeds.New(f)
	for _, seed := range mixedSeeds {
		corpus.Add(seed...)
	}

	f.Fuzz(func(t *testing.T, version uint8, method string, path []byte) {})
}

func FuzzFixedSeedCorpus(f *testing.F) {
	corpus := ossfuzzseeds.New(f)
	for _, seed := range fixedSeeds {
		corpus.Add(seed...)
	}

	f.Fuzz(func(t *testing.T, enabled bool, code uint32, value float64) {})
}

func assertCorpusFiles(t *testing.T, corpusDir string, seeds [][]any) {
	t.Helper()

	entries, err := os.ReadDir(corpusDir)
	require.NoError(t, err)
	require.Len(t, entries, len(seeds))

	want := make(map[string]struct{}, len(seeds))
	for _, seed := range seeds {
		entry, err := ossfuzzseeds.OSSFuzzCorpusEntry(seed...)
		require.NoError(t, err)
		want[string(entry)] = struct{}{}
	}

	for _, entry := range entries {
		got, err := os.ReadFile(corpusDir + "/" + entry.Name())
		require.NoError(t, err, "reading corpus file %s", entry.Name())
		require.Contains(t, want, string(got), "unexpected corpus file %s", entry.Name())
		delete(want, string(got))
	}
	require.Empty(t, want)
}

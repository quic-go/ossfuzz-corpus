package fuzzhelper_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"reflect"
	"strings"
	"testing"

	fuzzhelper "github.com/quic-go/ossfuzz-corpus"

	"github.com/AdamKorcz/go-118-fuzz-build/input"
)

func TestOSSFuzzCorpusEntryRoundTripWithNativeGoV2(t *testing.T) {
	cases := []struct {
		name string
		args []any
	}{
		{"bool true", []any{true}},
		{"bool false", []any{false}},
		{"int 42", []any{int(42)}},
		{"int8 -12", []any{int8(-12)}},
		{"int16 -300", []any{int16(-300)}},
		{"int32 200", []any{int32(200)}},
		{"int64 negative", []any{int64(-0x112233445566778)}},
		{"uint 42", []any{uint(42)}},
		{"uint8 200", []any{uint8(200)}},
		{"uint16 0x1234", []any{uint16(0x1234)}},
		{"uint32 0xdeadbeef", []any{uint32(0xdeadbeef)}},
		{"uint64 big", []any{uint64(0x1122334455667788)}},
		{"float32", []any{float32(1.25)}},
		{"float64", []any{float64(-1234.5)}},
		{"string", []any{"hello world"}},
		{"[]byte long", []any{[]byte("this is longer than 255 bytes - proves dynamic data works")}},
		{"two dynamic args", []any{"foo", []byte("bar")}},
		{"three dynamic args", []any{"a", []byte("bc"), "def"}},
		{"four dynamic args uneven", []any{"", []byte("abc"), "defgh", []byte("ij")}},
		{"five dynamic args mixed with fixed", []any{uint16(0x1234), "a", []byte("bc"), true, "def", []byte("ghij"), "klmno"}},
		{"mixed", []any{true, uint32(42), "foo", []byte("bar"), uint64(0xffffffffffffffff)}},
		{"dynamic before fixed", []any{"foo", uint32(42), []byte("bar"), false}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := fuzzhelper.OSSFuzzCorpusEntry(tc.args...)
			if err != nil {
				t.Fatal(err)
			}

			got := consumeWithOSSFuzzNativeGoV2(t, entry, tc.args)
			if !reflect.DeepEqual(got, tc.args) {
				t.Fatalf("expected %#v, got %#v", tc.args, got)
			}
		})
	}
}

func TestOSSFuzzCorpusEntryRandomizedRoundTripWithNativeGoV2(t *testing.T) {
	for i := range 1000 {
		var seed [32]byte
		if _, err := rand.Read(seed[:]); err != nil {
			t.Fatal(err)
		}

		t.Run(fmt.Sprintf("run %d", i+1), func(t *testing.T) {
			t.Logf("seed: %x", seed)

			chacha8 := mrand.NewChaCha8(seed)
			rng := mrand.New(chacha8)

			args := make([]any, 1+rng.IntN(10))
			for i := range args {
				switch rng.IntN(15) {
				case 0:
					b := make([]byte, rng.IntN(513))
					chacha8.Read(b)
					args[i] = b
				case 1:
					b := make([]byte, rng.IntN(513))
					chacha8.Read(b)
					args[i] = string(b)
				case 2:
					args[i] = rng.IntN(2) == 1
				case 3:
					args[i] = rng.IntN(1<<30) - 1<<29
				case 4:
					args[i] = int8(rng.IntN(256) - 128)
				case 5:
					args[i] = int16(rng.IntN(1<<16) - 1<<15)
				case 6:
					args[i] = int32(rng.Uint64())
				case 7:
					args[i] = int64(rng.Uint64())
				case 8:
					args[i] = uint(rng.Uint64() % (1 << 30))
				case 9:
					args[i] = uint8(rng.Uint64())
				case 10:
					args[i] = uint16(rng.Uint64())
				case 11:
					args[i] = uint32(rng.Uint64())
				case 12:
					args[i] = rng.Uint64()
				case 13:
					args[i] = float32(rng.Float64()*2_000_000 - 1_000_000)
				case 14:
					args[i] = rng.Float64()*2_000_000_000_000 - 1_000_000_000_000
				}
			}

			types := make([]string, len(args))
			for i, arg := range args {
				types[i] = strings.ReplaceAll(reflect.TypeOf(arg).String(), "[]uint8", "[]byte")
			}
			t.Logf("types: %v", types)

			entry, err := fuzzhelper.OSSFuzzCorpusEntry(args...)
			if errors.Is(err, fuzzhelper.ErrUnencodableDynamicCorpusArgs) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatalf("args %#v: %v", args, err)
			}

			got := consumeWithOSSFuzzNativeGoV2(t, entry, args)
			if !reflect.DeepEqual(got, args) {
				t.Fatalf("expected %#v, got %#v", args, got)
			}
		})
	}
}

func consumeWithOSSFuzzNativeGoV2(t *testing.T, entry []byte, args []any) []any {
	t.Helper()

	argTypes := make([]reflect.Type, 0, len(args)+1)
	argTypes = append(argTypes, reflect.TypeFor[*testing.T]())
	for _, arg := range args {
		argTypes = append(argTypes, reflect.TypeOf(arg))
	}

	var got []any
	fn := reflect.MakeFunc(
		reflect.FuncOf(argTypes, nil, false),
		func(values []reflect.Value) []reflect.Value {
			got = make([]any, 0, len(values)-1)
			for _, value := range values[1:] {
				got = append(got, value.Interface())
			}
			return nil
		},
	)

	input.NewSource(entry).FillAndCall(fn.Interface(), reflect.ValueOf(new(testing.T)))
	return got
}

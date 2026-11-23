package token

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadHiddenInput(t *testing.T) {
	for _, tc := range []struct {
		input, line, leftover string
	}{
		{"a.b.c\r", "a.b.c", ""},
		{"a.b.c\r\n", "a.b.c", "\n"},
		{"a.b.c", "a.b.c", ""},
		{"{\n  \"access_token\": \"a.b.c\"\n}\n", "{", "  \"access_token\": \"a.b.c\"\n}\n"},
		{"a.b.x\x7fc\r", "a.b.c", ""},
		{"a.b.x\bc\r", "a.b.c", ""},
		{"wrong\x15a.b.c\r", "a.b.c", ""},
		{"a.\x1b[Db.c\x1bOA\r", "a.b.c", ""},
		{"a.b\x1b[1;5C.c\r", "a.b.c", ""},
		{"a.b\x1bx.c\r", "a.b.c", ""},
		{"a.\tb.c\r", "a.b.c", ""},
		{"ab\x04c\r", "abc", ""},
		{"\x04", "", ""},
		{"a.b.c\x03rest", "", "rest"},
		{"\u05d3\u05e0\u05d4\x7f\r", "\u05d3\u05e0", ""},
	} {
		line, leftover, err := readHiddenInput(strings.NewReader(tc.input))
		require.NoError(t, err, tc.input)
		assert.Equal(t, tc.line, line, tc.input)
		assert.Equal(t, tc.leftover, leftover, tc.input)
	}
}

func TestReadHiddenInput_LongLineAcrossReads(t *testing.T) {
	token := strings.Repeat("a", 10000)
	line, leftover, err := readHiddenInput(iotest.OneByteReader(strings.NewReader(token + "\r")))
	require.NoError(t, err)
	assert.Equal(t, token, line)
	assert.Empty(t, leftover)
}

func TestReadHiddenInput_SizeLimit(t *testing.T) {
	line, _, err := readHiddenInput(strings.NewReader(strings.Repeat("a", maxTokenInput) + "\r"))
	require.NoError(t, err)
	assert.Len(t, line, maxTokenInput)
	_, _, err = readHiddenInput(strings.NewReader(strings.Repeat("a", maxTokenInput+1) + "\r"))
	assert.ErrorContains(t, err, "larger than 64 KiB")
}

func TestReadHiddenInput_ReadError(t *testing.T) {
	_, _, err := readHiddenInput(iotest.ErrReader(errors.New("boom")))
	assert.ErrorContains(t, err, "boom")
}

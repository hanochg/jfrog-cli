package token

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

const (
	keyCtrlC     = 0x03
	keyCtrlD     = 0x04
	keyCtrlH     = 0x08
	keyCtrlU     = 0x15
	keyEscape    = 0x1b
	keyBackspace = 0x7f

	multiLineInputError  = "the pasted text has more than one line, so it was discarded. Paste the token on its own, or pass it with --token-file=<path> or through a pipe"
	visibleTerminalError = "this terminal can't hide the token as you type it. Pass it with --token-file=<path> or through a pipe"
)

func terminalReader() func(prompt string) (string, error) {
	switch fd := os.Stdin.Fd(); {
	case term.IsTerminal(int(fd)):
		return readHiddenLine
	case isatty.IsCygwinTerminal(fd):
		return func(string) (string, error) { return "", errorutils.CheckErrorf(visibleTerminalError) }
	default:
		return nil
	}
}

func readHiddenLine(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	defer func() { _ = term.Restore(fd, state) }()
	_, _ = fmt.Fprint(os.Stderr, prompt)
	line, leftover, err := readHiddenInput(os.Stdin)
	leftover += discardPendingInput(fd)
	_, _ = fmt.Fprint(os.Stderr, "\r\n")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(leftover) != "" {
		return "", errorutils.CheckErrorf(multiLineInputError)
	}
	return line, nil
}

func readHiddenInput(input io.Reader) (line, leftover string, err error) {
	var value []byte
	inEscape, inSequence := false, false
	buf := make([]byte, 4096)
	for {
		n, readErr := input.Read(buf)
		for i := 0; i < n; i++ {
			b := buf[i]
			switch {
			case inSequence:
				inSequence = b < 0x40 || b > 0x7e
			case inEscape:
				inEscape, inSequence = false, b == '[' || b == 'O'
			case b == keyEscape:
				inEscape = true
			case b == '\r' || b == '\n':
				return string(value), string(buf[i+1 : n]), nil
			case b == keyCtrlC || b == keyCtrlD && len(value) == 0:
				return "", string(buf[i+1 : n]), nil
			case b == keyBackspace || b == keyCtrlH:
				_, size := utf8.DecodeLastRune(value)
				value = value[:len(value)-size]
			case b == keyCtrlU:
				value = value[:0]
			case b < 0x20:
			case len(value) == maxTokenInput:
				return "", string(buf[i+1 : n]), errorutils.CheckErrorf("the token input is larger than 64 KiB")
			default:
				value = append(value, b)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return string(value), "", nil
		}
		if readErr != nil {
			return "", "", errorutils.CheckError(readErr)
		}
	}
}

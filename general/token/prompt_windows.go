//go:build windows

package token

import (
	"time"

	"golang.org/x/sys/windows"
)

func discardPendingInput(fd int) string {
	time.Sleep(100 * time.Millisecond)
	_ = windows.FlushConsoleInputBuffer(windows.Handle(fd))
	return ""
}

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos && !windows

package token

func discardPendingInput(int) string {
	return ""
}

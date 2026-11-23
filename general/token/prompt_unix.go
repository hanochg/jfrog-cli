//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package token

import "golang.org/x/sys/unix"

func discardPendingInput(fd int) string {
	termios, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return ""
	}
	termios.Cc[unix.VMIN] = 0
	termios.Cc[unix.VTIME] = 1
	if err = unix.IoctlSetTermios(fd, ioctlSetTermios, termios); err != nil {
		return ""
	}
	var pending []byte
	buf := make([]byte, 4096)
	for len(pending) <= maxTokenInput {
		n, err := unix.Read(fd, buf)
		if n <= 0 || err != nil {
			break
		}
		pending = append(pending, buf[:n]...)
	}
	return string(pending)
}

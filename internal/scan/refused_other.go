//go:build !windows

package scan

import (
	"errors"
	"syscall"
)

func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

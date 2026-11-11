package scan

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is WSAECONNREFUSED. On Windows the net package surfaces the
// raw Winsock error, which does not match syscall.ECONNREFUSED.
const wsaeconnrefused syscall.Errno = 10061

func isRefused(err error) bool {
	return errors.Is(err, wsaeconnrefused) || errors.Is(err, syscall.ECONNREFUSED)
}

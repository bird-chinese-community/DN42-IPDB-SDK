package ipdb

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"time"
)

// Windows error codes that a reader holding a file open without delete sharing
// causes in a writer's rename or removal.
const (
	errorAccessDenied     syscall.Errno = 5
	errorSharingViolation syscall.Errno = 32
)

// retryOnDenied is true where readers can block a writer's rename and removal.
var retryOnDenied = runtime.GOOS == "windows"

func isDenied(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == errorAccessDenied || errno == errorSharingViolation)
}

// retryWhileDenied runs operation and, where retryOnDenied is set, repeats it
// every lockPollDelay while it fails with access denied or a sharing violation,
// until ctx ends.
func retryWhileDenied(ctx context.Context, operation func() error) error {
	for {
		err := operation()
		if err == nil || !retryOnDenied || !isDenied(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(lockPollDelay):
		}
	}
}

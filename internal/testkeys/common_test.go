package testkeys_test

import (
	"testing"
)

func shouldPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("%s => should panic, but did not", t.Name())
}

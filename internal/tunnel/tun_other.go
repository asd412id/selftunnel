//go:build !windows
// +build !windows

package tunnel

import "fmt"

// WindowsTUN is only available on Windows
type WindowsTUN struct{}

func createWindowsTUN(name string, mtu int) (*WindowsTUN, error) {
	return nil, fmt.Errorf("Windows TUN is not supported on this platform")
}

func (w *WindowsTUN) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("not supported")
}

func (w *WindowsTUN) Write(buf []byte) (int, error) {
	return 0, fmt.Errorf("not supported")
}

func (w *WindowsTUN) Close() error {
	return nil
}

func (w *WindowsTUN) Name() string {
	return ""
}

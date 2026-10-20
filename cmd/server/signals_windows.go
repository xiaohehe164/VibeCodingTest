//go:build windows

package main

import "os"

func gracefulSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func isReloadSignal(os.Signal) bool {
	return false
}

// Package version holds build metadata injected at link time.
package version

// Version is overridden with -ldflags "-X banner-fingerprint/internal/version.Version=x.y.z".
var Version = "1.0.0"

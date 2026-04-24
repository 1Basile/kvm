//go:build !linux || !arm

package kvm

func audioStart() {}
func audioStop()  {}
func micStop()    {}

// micStart stub — no-op on non-ARM/non-Linux builds.
// The real signature accepts a *webrtc.TrackRemote but we import webrtc only
// in the linux+arm build. Use interface{} to avoid the import here.
func micStart(_ interface{}) {}

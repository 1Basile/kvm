package usbgadget

// uac2AudioConfig configures the USB Audio Class 2 gadget function.
// From the target machine's perspective this appears as a USB audio device
// with both a microphone input and speaker output.
//
// From the KVM's perspective:
//   - Writing PCM to the ALSA playback device → target hears it as microphone input
//   - Reading PCM from the ALSA capture device → what the target plays on its speakers
var uac2AudioConfig = gadgetConfigItem{
	order:      2500,
	device:     "uac2.usb0",
	path:       []string{"functions", "uac2.usb0"},
	configPath: []string{"uac2.usb0"},
	attrs: gadgetAttributes{
		// Playback direction: KVM → Target (appears as microphone to target)
		"p_chmask": "3",     // stereo (bits: ch0=1, ch1=2)
		"p_srate":  "48000", // 48 kHz — matches WebRTC / Opus clock rate
		"p_ssize":  "2",     // 16-bit samples
		// Capture direction: Target → KVM (appears as speaker output to target)
		"c_chmask": "3",     // stereo
		"c_srate":  "48000", // 48 kHz
		"c_ssize":  "2",     // 16-bit samples
		// Increase USB request count to grow ALSA ring buffer from ~8ms to
		// ~64ms so the capture goroutine tolerates scheduling jitter.
		"req_number": "16",
	},
}

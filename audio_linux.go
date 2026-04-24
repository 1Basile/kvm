//go:build linux && arm

package kvm

/*
#cgo LDFLAGS: -lopus
#include <opus/opus.h>
#include <stdlib.h>

static int opus_encoder_reset(OpusEncoder *st) {
    return opus_encoder_ctl(st, OPUS_RESET_STATE);
}
*/
import "C"

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/yobert/alsa"
	"github.com/yobert/alsa/alsatype"
)

const (
	audioSampleRate   = 48000
	audioChannels     = 2
	audioFrameSamples = 960 // 20 ms at 48 kHz
)

// audioCapture reads HDMI audio from the ALSA capture device, encodes it to
// Opus, and writes samples to the current WebRTC session's audio track.
type audioCapture struct {
	mu     sync.Mutex
	stopCh chan struct{}
}

var globalAudio = &audioCapture{}

func audioStart() {
	globalAudio.mu.Lock()
	defer globalAudio.mu.Unlock()

	if globalAudio.stopCh != nil {
		return // already running
	}
	globalAudio.stopCh = make(chan struct{})
	go globalAudio.run(globalAudio.stopCh)
}

func audioStop() {
	globalAudio.mu.Lock()
	defer globalAudio.mu.Unlock()

	if globalAudio.stopCh == nil {
		return
	}
	close(globalAudio.stopCh)
	globalAudio.stopCh = nil
}

func (a *audioCapture) run(stopCh chan struct{}) {
	audioLogger.Info().Msg("starting HDMI audio capture")

	select {
	case <-stopCh:
		return
	case <-time.After(500 * time.Millisecond):
	}

	enc, err := newOpusEncoder(audioSampleRate, audioChannels)
	if err != nil {
		audioLogger.Error().Err(err).Msg("failed to create Opus encoder")
		return
	}
	defer enc.close()

	// pcmCh passes 48-frame (1ms) chunks from the reader goroutine to the
	// encoder goroutine. Buffer holds ~200ms so the reader is never blocked
	// by encoding time on the slow ARM CPU.
	// Using a fixed-size array type avoids per-read heap allocation.
	const chunkFrames = 48
	type pcmChunk [chunkFrames * audioChannels]int16
	pcmCh := make(chan pcmChunk, 200)

	// readerReset is set by the reader goroutine whenever it reopens the
	// device after an XRUN. The encoder flushes pcmAccum on the next chunk
	// so stale pre-gap samples don't get mixed into the new audio stream.
	var readerReset atomic.Bool

	// --- reader goroutine: ALSA → pcmCh -----------------------------------
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// Raise this OS thread to SCHED_FIFO so the OS scheduler cannot
		// preempt it long enough to starve the UAC2 buffer (8.3 ms period).
		alsaSetRealtimePriority()

		chunkData := make([]byte, chunkFrames*audioChannels*2)
		var readErr int64

		for {
			select {
			case <-stopCh:
				close(pcmCh)
				return
			default:
			}

			dev, err := openUAC2CaptureDevice()
			if err != nil {
				select {
				case <-stopCh:
					close(pcmCh)
					return
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}
			if err := dev.Prepare(); err != nil {
				dev.Close()
				select {
				case <-stopCh:
					close(pcmCh)
					return
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			alsaFixSwParams(dev, chunkFrames) //nolint: errcheck

			audioLogger.Info().Msg("audio capture running")

			for {
				select {
				case <-stopCh:
					dev.Close()
					close(pcmCh)
					return
				default:
				}
				if err := dev.Read(chunkData); err != nil {
					readErr++
					if readErr%200 == 1 {
						audioLogger.Debug().Err(err).Int64("read_err", readErr).
							Msg("ALSA read error")
					}
					readerReset.Store(true)
					// Fast recovery: reset stream position via ioctl without
					// closing the fd. If the kernel accepts it, capture
					// resumes in microseconds instead of milliseconds.
					if alsaRecoverXRUN(dev) == nil {
						continue
					}
					// Kernel rejected fast recovery — fall back to close+reopen.
					break
				}
				var chunk pcmChunk
				copy(chunk[:], bytesToInt16(chunkData))
				select {
				case pcmCh <- chunk:
				default:
					// channel full — drop oldest sample to avoid blocking reader
				}
			}
			dev.Close()
			select {
			case <-stopCh:
				close(pcmCh)
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	// --- encoder goroutine: pcmCh → Opus → WebRTC -------------------------
	opusBuf := make([]byte, 4000)
	// Pre-allocate with extra headroom so accumulation never triggers a copy.
	pcmAccum := make([]int16, 0, (audioFrameSamples+chunkFrames)*audioChannels*2)

	for chunk := range pcmCh {
		// After XRUN recovery, flush the partial-frame accumulator and reset
		// the Opus encoder's history. The encoder's internal memory still
		// reflects pre-gap audio; encoding fresh samples against that history
		// produces a smear artifact at the gap boundary regardless of codec mode.
		if readerReset.CompareAndSwap(true, false) {
			pcmAccum = pcmAccum[:0]
			enc.reset()
			// Don't drain pcmCh here — fast PREPARE recovery fills it
			// with fresh samples immediately, so draining would just discard
			// valid audio. The backlog check below handles slow close+reopen.
			continue
		}

		// If the encoder has fallen behind real-time (large backlog), drain
		// to avoid blasting a burst of late frames to the browser.
		if len(pcmCh) > cap(pcmCh)*3/4 {
			pcmAccum = pcmAccum[:0]
			enc.reset()
			for len(pcmCh) > 5 {
				<-pcmCh
			}
			continue
		}

		pcmAccum = append(pcmAccum, chunk[:]...)

		for len(pcmAccum) >= audioFrameSamples*audioChannels {
			n, err := enc.encode(pcmAccum[:audioFrameSamples*audioChannels], opusBuf)
			// Shift accumulator in-place to avoid the slice walking off the
			// backing array, which would cause unbounded memory growth.
			n2 := copy(pcmAccum, pcmAccum[audioFrameSamples*audioChannels:])
			pcmAccum = pcmAccum[:n2]

			if err != nil {
				audioLogger.Warn().Err(err).Msg("Opus encode error")
				continue
			}
			if currentSession != nil && currentSession.AudioTrack != nil {
				opusFrame := make([]byte, n)
				copy(opusFrame, opusBuf[:n])
				if err := currentSession.AudioTrack.WriteSample(media.Sample{
					Data:     opusFrame,
					Duration: 20 * time.Millisecond,
				}); err != nil {
					audioLogger.Warn().Err(err).Msg("audio track write error")
				}
			}
		}
	}
}

// openUAC2CaptureDevice finds and opens the UAC2 capture device (card 1+),
// negotiates S16_LE stereo 48kHz, and returns it ready for Prepare().
func openUAC2CaptureDevice() (*alsa.Device, error) {
	cards, err := alsa.OpenCards()
	if err != nil {
		return nil, fmt.Errorf("OpenCards: %w", err)
	}
	defer alsa.CloseCards(cards)

	var dev, fallbackDev *alsa.Device
	for _, card := range cards {
		devices, err := card.Devices()
		if err != nil {
			continue
		}
		for _, d := range devices {
			if d.Type == alsa.PCM && d.Record {
				if card.Number != 0 {
					dev = d
				} else {
					fallbackDev = d
				}
				break
			}
		}
		if dev != nil {
			break
		}
	}
	if dev == nil {
		dev = fallbackDev
	}
	if dev == nil {
		return nil, fmt.Errorf("no ALSA PCM capture device found")
	}
	if err := dev.Open(); err != nil {
		return nil, fmt.Errorf("Open: %w", err)
	}
	if _, err := dev.NegotiateFormat(alsa.S16_LE); err != nil {
		dev.Close()
		return nil, fmt.Errorf("NegotiateFormat: %w", err)
	}
	if _, err := dev.NegotiateRate(audioSampleRate); err != nil {
		dev.Close()
		return nil, fmt.Errorf("NegotiateRate: %w", err)
	}
	if _, err := dev.NegotiateChannels(audioChannels); err != nil {
		dev.Close()
		return nil, fmt.Errorf("NegotiateChannels: %w", err)
	}
	return dev, nil
}

// bytesToInt16 reinterprets a []byte (S16_LE) as []int16 without copying.
func bytesToInt16(b []byte) []int16 {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Slice((*int16)(unsafe.Pointer(&b[0])), len(b)/2)
}

// opusEncoder is a minimal CGO wrapper around libopus for encoding only.
type opusEncoder struct {
	enc *C.OpusEncoder
}

func newOpusEncoder(sampleRate, channels int) (*opusEncoder, error) {
	var errCode C.int
	enc := C.opus_encoder_create(
		C.opus_int32(sampleRate),
		C.int(channels),
		C.OPUS_APPLICATION_AUDIO,
		&errCode,
	)
	if errCode != C.OPUS_OK {
		return nil, fmt.Errorf("opus_encoder_create error %d", int(errCode))
	}
	return &opusEncoder{enc: enc}, nil
}

func (e *opusEncoder) encode(pcm []int16, out []byte) (int, error) {
	n := C.opus_encode(
		e.enc,
		(*C.opus_int16)(unsafe.Pointer(&pcm[0])),
		C.int(audioFrameSamples),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.opus_int32(len(out)),
	)
	if n < 0 {
		return 0, fmt.Errorf("opus_encode error %d", int(n))
	}
	return int(n), nil
}

func (e *opusEncoder) reset() {
	C.opus_encoder_reset(e.enc)
}

func (e *opusEncoder) close() {
	if e.enc != nil {
		C.opus_encoder_destroy(e.enc)
		e.enc = nil
	}
}

// ---------------------------------------------------------------------------
// Mic input: browser WebRTC audio → Opus decode → UAC2 ALSA playback device
// ---------------------------------------------------------------------------

type micInput struct {
	mu     sync.Mutex
	stopCh chan struct{}
}

var globalMic = &micInput{}

// micStart begins receiving audio from the given WebRTC remote track and
// routing it to the UAC2 ALSA playback device so the target hears it as a
// USB microphone.  The argument is typed as interface{} so the stub in
// audio_other.go shares the same signature without importing pion/webrtc.
func micStart(v interface{}) {
	track, ok := v.(*webrtc.TrackRemote)
	if !ok {
		return
	}
	micStartInner(track)
}

func micStartInner(track *webrtc.TrackRemote) {
	globalMic.mu.Lock()
	defer globalMic.mu.Unlock()

	if globalMic.stopCh != nil {
		close(globalMic.stopCh)
	}
	globalMic.stopCh = make(chan struct{})
	go globalMic.run(track, globalMic.stopCh)
}


func micStop() {
	globalMic.mu.Lock()
	defer globalMic.mu.Unlock()

	if globalMic.stopCh == nil {
		return
	}
	close(globalMic.stopCh)
	globalMic.stopCh = nil
}

func (m *micInput) run(track *webrtc.TrackRemote, stopCh chan struct{}) {
	audioLogger.Info().Msg("starting mic input (browser → UAC2)")

	dec, err := newOpusDecoder(audioSampleRate, audioChannels)
	if err != nil {
		audioLogger.Error().Err(err).Msg("failed to create Opus decoder")
		return
	}
	defer dec.close()

	// rtpCh decouples the blocking track.ReadRTP() call from the ALSA writer
	// so that stopCh can interrupt cleanly without waiting for the next packet.
	rtpCh := make(chan []byte, 20)
	go func() {
		for {
			pkt, _, err := track.ReadRTP()
			if err != nil {
				close(rtpCh)
				return
			}
			if len(pkt.Payload) == 0 {
				continue
			}
			select {
			case rtpCh <- pkt.Payload:
			default: // drop if writer is behind
			}
		}
	}()

	pcmBuf := make([]int16, audioFrameSamples*audioChannels)

	for {
		dev, err := openUAC2PlaybackDevice()
		if err != nil {
			select {
			case <-stopCh:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		if _, err := dev.NegotiateFormat(alsa.S16_LE); err != nil {
			dev.Close()
			audioLogger.Error().Err(err).Msg("mic: NegotiateFormat failed")
			return
		}
		if _, err := dev.NegotiateRate(audioSampleRate); err != nil {
			dev.Close()
			audioLogger.Error().Err(err).Msg("mic: NegotiateRate failed")
			return
		}
		if _, err := dev.NegotiateChannels(audioChannels); err != nil {
			dev.Close()
			audioLogger.Error().Err(err).Msg("mic: NegotiateChannels failed")
			return
		}
		if err := dev.Prepare(); err != nil {
			dev.Close()
			audioLogger.Error().Err(err).Msg("mic: Prepare failed")
			return
		}
		alsaFixSwParamsPlayback(dev) //nolint: errcheck
		audioLogger.Info().Msg("mic input running")

		writeErr := false
		for !writeErr {
			select {
			case <-stopCh:
				dev.Close()
				audioLogger.Info().Msg("mic input stopped")
				return
			case payload, ok := <-rtpCh:
				if !ok {
					dev.Close()
					audioLogger.Info().Msg("mic track closed")
					return
				}
				frames, err := dec.decode(payload, pcmBuf)
				if err != nil {
					audioLogger.Warn().Err(err).Msg("Opus decode error")
					continue
				}
				if err := dev.Write(int16ToBytes(pcmBuf[:frames*audioChannels]), frames); err != nil {
					audioLogger.Debug().Err(err).Msg("UAC2 playback write error, reopening")
					writeErr = true
				}
			}
		}
		dev.Close()
	}
}

// openUAC2PlaybackDevice finds and opens the first ALSA PCM playback device
// that is NOT the HDMI capture card (card 0 = TC358743).
func openUAC2PlaybackDevice() (*alsa.Device, error) {
	cards, err := alsa.OpenCards()
	if err != nil {
		return nil, fmt.Errorf("ALSA OpenCards: %w", err)
	}
	defer alsa.CloseCards(cards)

	for _, card := range cards {
		if card.Number == 0 {
			continue // skip TC358743 capture card
		}
		devices, err := card.Devices()
		if err != nil {
			continue
		}
		for _, dev := range devices {
			if dev.Type == alsa.PCM && dev.Play {
				if err := dev.Open(); err == nil {
					return dev, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no UAC2 playback device found (card 1+)")
}

// int16ToBytes reinterprets []int16 as []byte (little-endian, no copy).
func int16ToBytes(s []int16) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), len(s)*2)
}

// opusDecoder wraps libopus decoding.
type opusDecoder struct {
	dec *C.OpusDecoder
}

func newOpusDecoder(sampleRate, channels int) (*opusDecoder, error) {
	var errCode C.int
	dec := C.opus_decoder_create(C.opus_int32(sampleRate), C.int(channels), &errCode)
	if errCode != C.OPUS_OK {
		return nil, fmt.Errorf("opus_decoder_create error %d", int(errCode))
	}
	return &opusDecoder{dec: dec}, nil
}

// decode decodes an Opus packet into pcm (interleaved int16).
// Returns the number of decoded frames (samples per channel).
func (d *opusDecoder) decode(data []byte, pcm []int16) (int, error) {
	n := C.opus_decode(
		d.dec,
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.opus_int32(len(data)),
		(*C.opus_int16)(unsafe.Pointer(&pcm[0])),
		C.int(len(pcm)/audioChannels), // max_frame_size = samples per channel
		0,                              // decode_fec
	)
	if n < 0 {
		return 0, fmt.Errorf("opus_decode error %d", int(n))
	}
	return int(n), nil
}

func (d *opusDecoder) close() {
	if d.dec != nil {
		C.opus_decoder_destroy(d.dec)
		d.dec = nil
	}
}

// alsaFixSwParams corrects sw_params on an ALSA capture device after
// yobert/alsa's Prepare() sets values that are wrong for capture use:
//   - AvailMin = buf_size  → blocks until buffer is full (overrun condition)
//   - StartThreshold = buf_size → capture never auto-starts
//
// Fixes:
//   - AvailMin = 1         → unblock as soon as any frame is available
//   - StartThreshold = 1   → start capture immediately on first read
func alsaFixSwParams(dev *alsa.Device, availMin int) error {
	v := reflect.ValueOf(dev).Elem()

	// Access unexported fh *os.File via unsafe reflection.
	fhField := v.FieldByName("fh")
	fh := *(**os.File)(unsafe.Pointer(fhField.UnsafeAddr()))
	fd := fh.Fd()

	// Read current sw_params so we preserve all other fields.
	swField := v.FieldByName("swparams")
	sw := *(*alsatype.SwParams)(unsafe.Pointer(swField.UnsafeAddr()))

	bufSize := sw.StartThreshold                   // yobert/alsa sets StartThreshold = buf_size
	sw.AvailMin = alsatype.Uframes(availMin)       // unblock after one USB packet worth of data
	sw.StartThreshold = 1          // start capture on first read immediately

	// SNDRV_PCM_IOCTL_SW_PARAMS = _IOWR('A', 0x13, snd_pcm_sw_params)
	swSize := uint16(unsafe.Sizeof(sw))
	swIoctl := uintptr(3)<<30 | uintptr(swSize)<<16 | uintptr(0x4113)

	audioLogger.Debug().
		Uint32("buf_size", uint32(bufSize)).
		Uint16("sw_params_size", swSize).
		Msg("alsaFixSwParams: issuing SW_PARAMS ioctl")

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, swIoctl,
		uintptr(unsafe.Pointer(&sw))); errno != 0 {
		return fmt.Errorf("SNDRV_PCM_IOCTL_SW_PARAMS: %v", errno)
	}

	audioLogger.Debug().
		Uint32("avail_min_after", uint32(sw.AvailMin)).
		Uint32("start_threshold_after", uint32(sw.StartThreshold)).
		Uint32("stop_threshold_after", uint32(sw.StopThreshold)).
		Msg("alsaFixSwParams: succeeded")

	return nil
}

// alsaFixSwParamsPlayback corrects sw_params on an ALSA playback device.
// yobert/alsa sets StartThreshold = buf_size, meaning playback won't start
// until the buffer is completely full — adding a full buffer-worth of latency.
// Setting StartThreshold = 1 starts playback on the first written sample.
func alsaFixSwParamsPlayback(dev *alsa.Device) error {
	v := reflect.ValueOf(dev).Elem()
	fhField := v.FieldByName("fh")
	fh := *(**os.File)(unsafe.Pointer(fhField.UnsafeAddr()))
	fd := fh.Fd()

	swField := v.FieldByName("swparams")
	sw := *(*alsatype.SwParams)(unsafe.Pointer(swField.UnsafeAddr()))

	sw.StartThreshold = 1 // start playback on first write, not when buffer is full
	sw.AvailMin = 1       // wake writer as soon as any space is available

	swSize := uint16(unsafe.Sizeof(sw))
	swIoctl := uintptr(3)<<30 | uintptr(swSize)<<16 | uintptr(0x4113)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, swIoctl,
		uintptr(unsafe.Pointer(&sw))); errno != 0 {
		return fmt.Errorf("SNDRV_PCM_IOCTL_SW_PARAMS (playback): %v", errno)
	}
	return nil
}

// alsaSetRealtimePriority sets SCHED_FIFO priority 10 on the calling thread.
// Must be called after runtime.LockOSThread so it targets the right OS thread.
// Without real-time scheduling, the Linux CFS scheduler can preempt the audio
// reader for >8 ms, exhausting the UAC2 buffer and causing an XRUN.
func alsaSetRealtimePriority() {
	type schedParam struct{ priority int32 }
	param := schedParam{priority: 10}
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_SCHED_SETSCHEDULER,
		0, // current thread
		1, // SCHED_FIFO
		uintptr(unsafe.Pointer(&param)),
	)
	if errno != 0 {
		audioLogger.Warn().Int("errno", int(errno)).
			Msg("audio reader: SCHED_FIFO unavailable, XRUN risk is higher")
	} else {
		audioLogger.Info().Msg("audio reader: SCHED_FIFO priority 10 set")
	}
}

// alsaRecoverXRUN attempts fast XRUN recovery by issuing SNDRV_PCM_IOCTL_PREPARE
// without closing the device fd. On success capture resumes in microseconds;
// if the kernel rejects it (e.g. state machine mismatch) the caller falls back
// to a full device close+reopen.
func alsaRecoverXRUN(dev *alsa.Device) error {
	v := reflect.ValueOf(dev).Elem()
	fhField := v.FieldByName("fh")
	fh := *(**os.File)(unsafe.Pointer(fhField.UnsafeAddr()))
	fd := fh.Fd()
	// SNDRV_PCM_IOCTL_PREPARE = _IO('A', 0x40)
	const ioctlPrepare = uintptr(0x00004140)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlPrepare, 0); errno != 0 {
		return errno
	}
	return nil
}


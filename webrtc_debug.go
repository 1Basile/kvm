package kvm

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

const webrtcDebugLogPath = "/tmp/jetkvm-webrtc-debug.log"

var (
	webrtcDebugMu sync.Mutex
	webrtcDebugF  *os.File
)

func dbgLog(format string, args ...any) {
	webrtcDebugMu.Lock()
	defer webrtcDebugMu.Unlock()

	if webrtcDebugF == nil {
		var err error
		webrtcDebugF, err = os.OpenFile(webrtcDebugLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}
	}

	_, file, line, _ := runtime.Caller(1)
	// shorten file path to just filename
	for i := len(file) - 1; i >= 0; i-- {
		if file[i] == '/' {
			file = file[i+1:]
			break
		}
	}

	prefix := fmt.Sprintf("[%s] %s:%d  ", time.Now().UTC().Format("15:04:05.000"), file, line)
	msg := prefix + fmt.Sprintf(format, args...) + "\n"
	_, _ = webrtcDebugF.WriteString(msg)
}

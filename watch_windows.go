//go:build windows

package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
)

var lastGUIPulse int64

func watchGUI() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	flagged := false
	for range ticker.C {
		last := atomic.LoadInt64(&lastGUIPulse)
		age := time.Since(time.Unix(0, last))
		if last > 0 && age > 8*time.Second && !flagged {
			flagged = true
			stack := make([]byte, 1024*128)
			n := runtime.Stack(stack, true)
			appendLog(fmt.Sprintf("GUI WATCHDOG: no WM_TIMER for %s; goroutine stacks:\r\n%s", age.String(), stack[:n]))
		}
		if age < 4*time.Second {
			flagged = false
		}
	}
}
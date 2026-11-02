//go:build windows && amd64

package main

import _ "embed"

//go:embed assets/RutokenInspector_x86_worker.exe
var legacyWorker []byte
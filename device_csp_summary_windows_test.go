//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
)

func TestSourceHardwareCSPDoesNotMentionPrivateAPIs(t *testing.T) {
	script := comReadersScript
	for _, word := range []string{"ReadBinary(", "AuthenticateOwner(", "EnumFolders(", "SaveToFile(", "GetPrivateKey"} {
		if strings.Contains(script, word) {
			t.Fatalf("token metadata probe unexpectedly calls %s", word)
		}
	}
}
func TestWorkerDoesNotTouchCryptoProHDIMAGE(t *testing.T) {
	b, err := os.ReadFile("device_csp_summary_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, word := range []string{"MkdirAll(", "WriteFile(", "Remove(", "Rename(", "CopyFile("} {
		if strings.Contains(src, word) {
			t.Fatalf("read-only summary contains %s", word)
		}
	}
}
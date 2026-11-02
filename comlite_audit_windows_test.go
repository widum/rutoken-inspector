//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatCOMJScriptResult(t *testing.T) {
	cases := []struct {
		name, raw string
		err       error
		timedOut  bool
		want      string
	}{
		{"ok", "WSH_STARTED\r\nCOM_CREATED\r\nCOM_EXITING\r\n", nil, false, "успешно"},
		{"error", "WSH_STARTED\r\nCOM_ERR_0X80040154\r\n", errors.New("exit status 2"), false, "0x80040154"},
		{"null", "WSH_STARTED\r\nCOM_NULL\r\n", errors.New("exit status 3"), false, "пустой"},
		{"com hang", "WSH_STARTED\r\n", errors.New("signal: killed"), true, "при создании COM"},
		{"release hang", "WSH_STARTED\r\nCOM_CREATED\r\n", errors.New("signal: killed"), true, "при завершении"},
		{"host hang", "", errors.New("signal: killed"), true, "Windows Script Host"},
		{"host fail", "", errors.New("exit status 1"), false, "запустить JScript"},
		{"unknown output", "WSH_STARTED", nil, false, "неизвестный ответ"},
		{"empty successful output", "", nil, false, "завершился без вывода"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatCOMJScriptResult([]byte(tc.raw), tc.err, tc.timedOut)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("result %q, wanted %q", got, tc.want)
			}
		})
	}
}

func TestCOMProbeArgsKeepEchoEnabled(t *testing.T) {
	args := comProbeHostArgs(`C:\Temp\probe.js`)
	got := strings.Join(args, " ")
	if strings.Contains(strings.ToUpper(got), "//B") {
		t.Fatalf("//B would hide WScript.Echo diagnostics: %q", got)
	}
	if !strings.Contains(strings.ToUpper(got), "//I") {
		t.Fatalf("//I should explicitly enable diagnostics: %q", got)
	}
	if !strings.Contains(got, `C:\Temp\probe.js`) {
		t.Fatalf("script path missing: %q", got)
	}
}
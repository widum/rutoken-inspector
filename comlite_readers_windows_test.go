//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCOMReaderParseSuccess(t *testing.T) {
	raw := []byte("SCAN_START\r\nCOM_READY\r\nACQUIRE_OK\r\nCOUNT:1\r\nREADER:0:Aktiv%20Co.%20ruToken%200\r\nOPEN_OK:0\r\nMODEL:0:Rutoken%20S%2064K\r\nVERSION:0:3.1\r\nCLOSE_OK:0\r\nSCAN_FINISHED\r\nFREE_OK\r\n")
	got := formatCOMReaderResult(raw, nil, false)
	for _, needle := range []string{"Rutoken S 64K", "Aktiv Co. ruToken 0", "1."} {
		if !strings.Contains(got, needle) {
			t.Fatal(got)
		}
	}
}
func TestCOMReaderParseErrors(t *testing.T) {
	got := formatCOMReaderResult([]byte("SCAN_START\nCOM_READY\nACQUIRE_OK\nCOUNT:1\nREADER:0:A\nOPEN_ERROR:0:80040002\nSCAN_FINISHED\n"), nil, false)
	if !strings.Contains(got, "HRESULT 0x80040002") {
		t.Fatal(got)
	}
	got = formatCOMReaderResult([]byte("SCAN_START\nCOM_READY\n"), errors.New("killed"), true)
	if !strings.Contains(got, "Тайм-аут") {
		t.Fatal(got)
	}
}
func TestCOMReaderScriptIsMetadataOnly(t *testing.T) {
	for _, forbidden := range []string{"AuthenticateOwner", "ReadBinary", "EnumFolders", "SaveToFile", "GetRetryCounter", "BeginTransaction"} {
		if strings.Contains(comReadersScript, forbidden) {
			t.Fatalf("unexpected call %s", forbidden)
		}
	}
}
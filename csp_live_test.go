//go:build windows

package main

import "testing"

func TestParseCSPNames(t *testing.T) {
	in := "CSP v5\r\n\\\\.\\HDIMAGE\\A\r\n\\\\.\\SCARD\\X\r\n\\\\.\\HDIMAGE\\A\r\nOK.\n[ErrorCode: 0x00000000]\n"
	got := parseCSPNames(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique FQCNs, got %#v", got)
	}
	if got[0] != `\\.\HDIMAGE\A` {
		t.Fatal(got)
	}
}
func TestSuccessRequiresZeroCode(t *testing.T) {
	if !cspSucceeded("OK.\n[ErrorCode: 0x00000000]", nil) {
		t.Fatal("success not detected")
	}
	if cspSucceeded("ErrorCode: 0x8009000b", nil) {
		t.Fatal("failure mistaken as success")
	}
	if cspSucceeded("OK.", nil) {
		t.Fatal("unverified result mistaken as success")
	}
}
func TestNeverExtractableBlock(t *testing.T) {
	r := &scanReport{Authenticated: true, Objects: []objectInfo{{Class: "Закрытый ключ", Attributes: map[string]any{"CKA_EXTRACTABLE": false, "CKA_NEVER_EXTRACTABLE": true}}}}
	if !reportIsHardwareLocked(r) {
		t.Fatal("hardware key incorrectly marked exportable")
	}
	r.Objects[0].Attributes["CKA_NEVER_EXTRACTABLE"] = false
	if reportIsHardwareLocked(r) {
		t.Fatal("exportable key incorrectly blocked")
	}
}
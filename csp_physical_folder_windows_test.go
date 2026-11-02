//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPhysicalCSPFolders(t *testing.T) {
	before := map[string]string{"3072.000": `C:\\a\\3072.000`}
	after := map[string]string{"3072.000": `C:\\a\\3072.000`, "4098.000": `C:\\a\\4098.000`}
	got := newPhysicalCSPFolders(before, after)
	if len(got) != 1 || !strings.HasSuffix(got[0], "4098.000") {
		t.Fatalf("new folder detection: %q", got)
	}
	if got := newPhysicalCSPFolders(after, before); len(got) != 0 {
		t.Fatalf("deleted folder must not count as new: %q", got)
	}
}

func TestCheckPhysicalCSPNames(t *testing.T) {
	dir := t.TempDir()
	if checkPhysicalCSPNames(dir) == nil {
		t.Fatal("empty directory must fail")
	}
	for _, name := range sixCSPFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test-fixture-only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkPhysicalCSPNames(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "masks.key"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPhysicalCSPNames(dir); err == nil {
		t.Fatal("empty key file must fail")
	}
}
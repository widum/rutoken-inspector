package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeCSPArchive(t *testing.T, name string, invalid bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "backup.zip")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	w := zip.NewWriter(f)
	for _, n := range sixCSPFiles {
		if invalid && n == "name.key" {
			continue
		}
		wr, e := w.Create(name + "/" + n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = wr.Write([]byte("test-data-" + n)); e != nil {
			t.Fatal(e)
		}
	}
	wr, e := w.Create("4097.000/666")
	if e != nil {
		t.Fatal(e)
	}
	wr.Write([]byte("x"))
	w.Close()
	f.Close()
	return p
}
func TestImportCreatesSixFilesAndSkipsIncomplete(t *testing.T) {
	p := makeCSPArchive(t, "2560.000", false)
	dest := filepath.Join(t.TempDir(), "Crypto Pro")
	res, e := importCSPContainerZIP(p, dest)
	if e != nil {
		t.Fatal(e)
	}
	if len(res.Created) != 1 || res.Created[0] != "2560.000" {
		t.Fatalf("result %+v", res)
	}
	for _, n := range sixCSPFiles {
		b, e := os.ReadFile(filepath.Join(dest, "2560.000", n))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b, []byte("test-data-"+n)) {
			t.Fatalf("wrong content %s", n)
		}
	}
	if _, e := os.Stat(filepath.Join(dest, "4097.000")); !os.IsNotExist(e) {
		t.Fatal("should not import incomplete 4097.000")
	}
	res, e = importCSPContainerZIP(p, dest)
	if e != nil {
		t.Fatal(e)
	}
	if len(res.Created) != 0 || len(res.Skipped) != 1 {
		t.Fatalf("second import %+v", res)
	}
}
func TestNoPartialImport(t *testing.T) {
	p := makeCSPArchive(t, "3072.000", true)
	dest := filepath.Join(t.TempDir(), "Crypto Pro")
	_, e := importCSPContainerZIP(p, dest)
	if e == nil || !strings.Contains(e.Error(), "нет шестифайловых") {
		t.Fatalf("error expected %v", e)
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("destination should not exist")
	}
}
func TestDoNotOverwrite(t *testing.T) {
	p := makeCSPArchive(t, "3072.000", false)
	dest := filepath.Join(t.TempDir(), "Crypto Pro")
	os.MkdirAll(filepath.Join(dest, "3072.000"), 0700)
	os.WriteFile(filepath.Join(dest, "3072.000", "header.key"), []byte("EXISTING"), 0600)
	res, e := importCSPContainerZIP(p, dest)
	if e != nil {
		t.Fatal(e)
	}
	if len(res.Skipped) != 1 {
		t.Fatal(res)
	}
	b, _ := os.ReadFile(filepath.Join(dest, "3072.000", "header.key"))
	if string(b) != "EXISTING" {
		t.Fatal("overwrote existing container")
	}
}
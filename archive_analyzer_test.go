package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzerClassifies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample.zip")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for _, n := range cspFiles {
		w, e := z.Create("3072.000/" + n)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = w.Write([]byte("dummy"))
	}
	w, _ := z.Create("4097.000/666")
	_, _ = w.Write([]byte("data"))
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	got, e2 := analyzeZipText(p)
	if e2 != "" {
		t.Fatal(e2)
	}
	if !strings.Contains(got, "полный набор 6") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "4097.000") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "0/6") {
		t.Fatal(got)
	}
}
package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticCSPZip(t *testing.T, target string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "source.zip")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, name := range sixCSPFiles {
		h, err := w.Create(target + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Write([]byte("test-only-" + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}
func TestQuickImportZIPComplete(t *testing.T) {
	z := syntheticCSPZip(t, "3072.000")
	plan, err := quickSourcesZip(z)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "Crypto Pro")
	if err = planQuickNames(plan, dest); err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].Target != "3072.000" {
		t.Fatalf("unexpected target %q", plan.Candidates[0].Target)
	}
	_, err = installQuick(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sixCSPFiles {
		data, err := os.ReadFile(filepath.Join(dest, "3072.000", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, []byte("test-only-"+name)) {
			t.Errorf("bad key file %s", name)
		}
	}
}
func TestQuickImportCollision(t *testing.T) {
	z := syntheticCSPZip(t, "3072.000")
	dest := filepath.Join(t.TempDir(), "Crypto Pro")
	if err := os.MkdirAll(filepath.Join(dest, "3072.000"), 0700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dest, "3072.000", "marker")
	if err := os.WriteFile(original, []byte("KEEP"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, _ := quickSourcesZip(z)
	if err := planQuickNames(plan, dest); err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].Target == "3072.000" {
		t.Fatal("overwrite planned")
	}
	res, err := installQuick(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 1 {
		t.Fatal("no copy")
	}
	b, _ := os.ReadFile(original)
	if string(b) != "KEEP" {
		t.Fatal("original modified")
	}
}
func TestQuickRejectDiagnostic(t *testing.T) {
	file := filepath.Join(t.TempDir(), "dump.zip")
	f, _ := os.Create(file)
	w := zip.NewWriter(f)
	o, _ := w.Create("public/001_certificate.cer")
	_, _ = o.Write([]byte("fake"))
	_ = w.Close()
	_ = f.Close()
	_, err := quickSourcesZip(file)
	if err == nil || !strings.Contains(err.Error(), "не найдено") {
		t.Fatalf("unexpected error: %v", err)
	}
}
func TestQuickFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "2560.000")
	_ = os.MkdirAll(dir, 0700)
	for _, n := range sixCSPFiles {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600)
	}
	plan, err := quickSourcesDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := planQuickNames(plan, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := installQuick(plan); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyFilename(t *testing.T) {
	s := decodeLegacyFileName("#U041e#U041e#U041e #U041f#U0440#U0438#U043c#U0435#U0440")
	if s != "ООО Пример" {
		t.Fatalf("got %s", s)
	}
}
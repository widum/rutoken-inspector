//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic bytes check only the copier; they are not usable signing keys.
func TestPlanLocalCloneAndPreserveSource(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	root := filepath.Join(localAppData, "Crypto Pro")
	src := filepath.Join(root, "3072.000")
	if err := os.MkdirAll(src, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range sixCSPFiles {
		if err := os.WriteFile(filepath.Join(src, f), []byte("not-a-key:"+f), 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := planLocalCloneTest(src)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].Target == "3072.000" {
		t.Fatal("planned overwrite")
	}
	result, err := installQuick(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Created) != 1 {
		t.Fatalf("unexpected targets %v", result.Created)
	}
	for _, f := range sixCSPFiles {
		a, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(result.Destination, result.Created[0], f))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("bytes changed: %s", f)
		}
	}
}
func TestPlanLocalCloneRejectsNonLocalSource(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	arbitrary := filepath.Join(t.TempDir(), "3072.000")
	if err := os.MkdirAll(arbitrary, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range sixCSPFiles {
		if err := os.WriteFile(filepath.Join(arbitrary, f), []byte("fake"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := planLocalCloneTest(arbitrary); err == nil {
		t.Fatal("accepted source outside local Crypto Pro")
	}
}
func TestPlanLocalCloneRejectsIncompleteSource(t *testing.T) {
	app := t.TempDir()
	t.Setenv("LOCALAPPDATA", app)
	src := filepath.Join(app, "Crypto Pro", "1234.000")
	if err := os.MkdirAll(src, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "header.key"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := planLocalCloneTest(src); err == nil {
		t.Fatal("accepted an incomplete container")
	}
}
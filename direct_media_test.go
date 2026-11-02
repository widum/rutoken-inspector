package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverAccessibleContainers(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "2560.000")
	if e := os.Mkdir(valid, 0700); e != nil {
		t.Fatal(e)
	}
	for _, f := range sixCSPFiles {
		if e := os.WriteFile(filepath.Join(valid, f), []byte("test"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Mkdir(filepath.Join(root, "incomplete"), 0700); e != nil {
		t.Fatal(e)
	}
	plan, err := discoverAccessibleContainers([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 1 || !strings.HasSuffix(plan.Candidates[0].Source, "2560.000") {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
func TestDiscoverAccessibleContainersEmpty(t *testing.T) {
	_, err := discoverAccessibleContainers([]string{t.TempDir()})
	if err == nil {
		t.Fatal("expected no container error")
	}
}
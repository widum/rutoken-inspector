package main

import (
	"strings"
	"testing"
)

func TestSummarizeCSPInventory(t *testing.T) {
	names := []string{
		`\\.\HDIMAGE\00000000-0000-4000-8000-000000000001`,
		`\\.\HDIMAGE\00000000-0000-4000-8000-000000000002`,
		`\\.\Aktiv Co. ruToken 0\00000000-0000-4000-8000-000000000002`,
	}
	got, summary := summarizeCSPInventory(names)
	if len(got) != 3 || !strings.Contains(got[0], "ruToken") {
		t.Fatal(got)
	}
	if !strings.Contains(summary, "HDIMAGE — 2") || !strings.Contains(summary, "совпад") {
		t.Fatal(summary)
	}
	if matchingHDIMAGE(got[0], got) == "" {
		t.Fatal("match not found")
	}
	if matchingHDIMAGE(got[1], got) != "" {
		t.Fatal("HDIMAGE not source")
	}
}
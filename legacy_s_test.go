//go:build windows

package main

import "testing"

func TestLegacySDispatch(t *testing.T) {
	cases := []struct {
		model, label string
		expected     bool
	}{
		{"Rutoken S", "Rutoken S <no label>", true},
		{"Rutoken S 64K", "", true},
		{"Rutoken ECP", "Rutoken ECP <no label>", false},
		{"Rutoken Lite", "Rutoken Lite", false},
		{"", "Rutoken S <no label>", true},
	}
	for _, tc := range cases {
		got := isLegacyRutokenS(deviceInfo{Model: tc.model, Label: tc.label})
		if got != tc.expected {
			t.Errorf("isLegacyRutokenS(%q,%q)=%v want %v", tc.model, tc.label, got, tc.expected)
		}
	}
}
//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// planLocalCloneTest prepares a source in LOCALAPPDATA/Crypto Pro only.
// It never touches physical tokens and never opens the CSP API.
// The source must already contain all six .key files.
func planLocalCloneTest(src string) (*quickPlan, error) {
	if err := validateLocalCSPSource(src); err != nil {
		return nil, err
	}
	plan, err := quickSourcesDir(src)
	if err != nil {
		return nil, err
	}
	root, err := cspDestination()
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(src)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("символьная ссылка вместо обычного контейнера недопустима")
	}
	if err := planQuickNames(plan, root); err != nil {
		return nil, err
	}
	if len(plan.Candidates) != 1 || len(plan.Candidates[0].Keys) != 6 {
		return nil, errors.New("неполный набор .key в источнике")
	}
	target := filepath.Join(root, plan.Candidates[0].Target)
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(target)) {
		return nil, errors.New("источник и назначение совпадают")
	}
	if _, err := os.Lstat(target); err == nil || !os.IsNotExist(err) {
		return nil, errors.New("папка назначения занята")
	}
	return plan, nil
}
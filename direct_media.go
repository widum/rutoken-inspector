package main

// Filesystem-only direct copy of already accessible, complete six-file CSP
// containers from mounted media. This does not request token private-key
// values, issue smart-card APDUs, or bypass CryptoPro export restrictions.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// discoverAccessibleContainers checks a volume root and its immediate
// subdirectories only. No recursive scan of user data is performed.
func discoverAccessibleContainers(roots []string) (*quickPlan, error) {
	p := &quickPlan{Source: "Подключённые файловые USB-носители"}
	seen := map[string]bool{}
	for _, root := range roots {
		if root == "" {
			continue
		}
		var candidates []string
		candidates = append(candidates, root)
		entries, err := os.ReadDir(root)
		if err != nil {
			p.Ignored = append(p.Ignored, fmt.Sprintf("%s: %v", root, err))
			continue
		}
		for _, e := range entries {
			if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				candidates = append(candidates, filepath.Join(root, e.Name()))
			}
		}
		for _, dir := range candidates {
			key := strings.ToLower(filepath.Clean(dir))
			if seen[key] {
				continue
			}
			seen[key] = true
			part, err := quickSourcesDir(dir)
			if err == nil && len(part.Candidates) == 1 {
				candidate := part.Candidates[0]
				candidate.Source = dir
				p.Candidates = append(p.Candidates, candidate)
			}
		}
	}
	if len(p.Candidates) == 0 {
		return nil, errors.New("на подключённых файловых USB-носителях нет доступного контейнера из 6 файлов .key. Смарт-карта Рутокен S не является USB-диском; для неё этот способ неприменим")
	}
	sort.Slice(p.Candidates, func(i, j int) bool { return p.Candidates[i].Source < p.Candidates[j].Source })
	return p, nil
}
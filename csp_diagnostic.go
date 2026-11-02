package main

// OPTIONAL MANUAL TEST: places public PKCS#11 objects
// into a numerically named folder for user inspection. It is NOT a key backup.
// No fake .key files are generated.
import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type diagnosticCandidate struct {
	Source   string
	Target   string
	CertName string
	Files    map[string]quickEntry
}

func diagZIP(zipPath, dest string) (diagnosticCandidate, error) {
	var candidate diagnosticCandidate
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return candidate, err
	}
	defer z.Close()
	if len(z.File) > 500 {
		return candidate, errors.New("слишком много записей для диагностического ZIP")
	}
	var root string
	entries := map[string]quickEntry{}
	var cert *quickEntry
	var total uint64
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "\\") || path.Clean(f.Name) != f.Name {
			return candidate, errors.New("небезопасный путь ZIP")
		}
		if f.UncompressedSize64 > maxQuickFile {
			return candidate, fmt.Errorf("слишком крупный файл: %s", f.Name)
		}
		total += f.UncompressedSize64
		if total > maxQuickZIP {
			return candidate, errors.New("ZIP слишком большой")
		}
		full := unicodeZIPPath(f)
		folder, file := path.Split(full)
		folder = strings.TrimSuffix(folder, "/")
		// Recognize only documented public exports, not arbitrary token storage paths.
		wanted := false
		if folder == "public" {
			if file == "000_data.bin" || file == "001_certificate.cer" || file == "002_public_key.bin" {
				wanted = true
			}
		} else if numberedContainer.MatchString(folder) {
			if file == "16870" || file == "32768" || file == "666" || strings.EqualFold(path.Ext(file), ".cer") {
				wanted = true
			}
		}
		if !wanted {
			continue
		}
		if root != "" && root != folder {
			return candidate, errors.New("найдено несколько диагностических дампов; используйте отдельный ZIP")
		}
		root = folder
		member := f.Name
		entry := quickEntry{Name: file, Size: int64(f.UncompressedSize64), Open: func() (io.ReadCloser, error) { return reopenZIPMember(zipPath, member) }}
		if strings.EqualFold(path.Ext(file), ".cer") {
			cert = &entry
			continue
		}
		if entries[file].Open != nil {
			return candidate, errors.New("дублирующийся файл дампа")
		}
		entries[file] = entry
	}
	if root == "" || len(entries) == 0 {
		return candidate, errors.New("нет допустимых публичных объектов для теста; не является PKCS#11-дампом")
	}
	candidate.Source = root
	candidate.Files = entries
	if cert != nil {
		b, er := readQuick(*cert)
		if er != nil {
			return candidate, er
		}
		if !looksDERCertificate(b) {
			return candidate, errors.New("повреждённый сертификат")
		}
		org := certOrganization(b)
		nice := decodeLegacyFileName(strings.TrimSuffix(cert.Name, path.Ext(cert.Name)))
		if normalizedOrg(org) == normalizedOrg(nice) || org == "" {
			org = nice
		}
		org = safeCertName(strings.ReplaceAll(org, `"`, ""))
		if org == "" {
			org = "Сертификат"
		}
		candidate.CertName = org + ".cer"
		candidate.Files[candidate.CertName] = *cert
	}
	preferred := ""
	if numberedContainer.MatchString(root) {
		preferred = root
	}
	if preferred != "" && !takenQuick(dest, preferred, nil) {
		candidate.Target = preferred
	} else {
		for i := 8000; i < 9000; i++ {
			n := fmt.Sprintf("%d.000", i)
			if !takenQuick(dest, n, nil) {
				candidate.Target = n
				break
			}
		}
	}
	if candidate.Target == "" {
		return candidate, errors.New("нет свободных каталогов 8000–8999")
	}
	return candidate, nil
}
func installDiagnostic(c diagnosticCandidate, dest string) error {
	if err := os.MkdirAll(dest, 0700); err != nil {
		return err
	}
	target := filepath.Join(dest, c.Target)
	if takenQuick(dest, c.Target, nil) {
		return fmt.Errorf("папка %s уже существует", c.Target)
	}
	stage, err := os.MkdirTemp(dest, ".inspector-diagnostic-")
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			_ = os.RemoveAll(stage)
		}
	}()
	names := make([]string, 0, len(c.Files))
	for name := range c.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := c.Files[name]
		data, er := readQuick(entry)
		if er != nil {
			return er
		}
		er = writeQuick(filepath.Join(stage, name), data)
		if er != nil {
			return er
		}
	}
	if takenQuick(dest, c.Target, nil) {
		return errors.New("назначение занято")
	}
	if err := os.Rename(stage, target); err != nil {
		return err
	}
	finished = true
	return nil
}
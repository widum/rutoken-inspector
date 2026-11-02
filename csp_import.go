package main

// Import of pre-existing, user-supplied legacy CryptoPro FILE containers.
// No key material is generated, exported from the token, transformed or logged.
// The source archive must already contain six original *.key files per folder.

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var cspDirectory = regexp.MustCompile(`^[0-9]{1,12}\.000$`)
var sixCSPFiles = []string{"header.key", "masks.key", "masks2.key", "name.key", "primary.key", "primary2.key"}

const maxContainerBytes = 6 * 1024 * 1024

type cspImportCandidate struct {
	Name  string
	Files map[string]*zip.File
	Size  uint64
}

type cspImportResult struct {
	Created []string
	Skipped []string
	Ignored []string
	Target  string
}

// cspCandidates opens the ZIP and validates its complete candidate list.
// Only a directory named NNNN.000 with exactly six files is importable.
func cspCandidates(z *zip.ReadCloser) ([]cspImportCandidate, []string, error) {
	if len(z.File) > 2000 {
		return nil, nil, errors.New("слишком много записей в ZIP")
	}
	groups := make(map[string]map[string]*zip.File)
	ignored := make(map[string]bool)
	var total uint64
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// Reject unexpected paths and symlinks; do not unpack arbitrary names.
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("символические ссылки в архиве запрещены: %q", f.Name)
		}
		if strings.Contains(f.Name, "\\") || strings.HasPrefix(f.Name, "/") || path.Clean(f.Name) != f.Name {
			return nil, nil, fmt.Errorf("небезопасный ZIP-путь: %q", f.Name)
		}
		parts := strings.Split(f.Name, "/")
		if len(parts) != 2 || !cspDirectory.MatchString(parts[0]) {
			if len(parts) > 0 && cspDirectory.MatchString(parts[0]) {
				ignored[parts[0]] = true
			}
			continue
		}
		dir, name := parts[0], parts[1]
		if name == "" {
			continue
		}
		known := false
		for _, req := range sixCSPFiles {
			if name == req {
				known = true
				break
			}
		}
		if !known {
			ignored[dir] = true
			continue
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > 1024*1024 {
			return nil, nil, fmt.Errorf("недопустимый размер %s", f.Name)
		}
		total += f.UncompressedSize64
		if total > 40*1024*1024 {
			return nil, nil, errors.New("общий размер ключевых файлов слишком велик")
		}
		if groups[dir] == nil {
			groups[dir] = make(map[string]*zip.File)
		}
		if groups[dir][name] != nil {
			return nil, nil, fmt.Errorf("дублирующаяся запись %s", f.Name)
		}
		groups[dir][name] = f
	}
	var candidates []cspImportCandidate
	for dir, files := range groups {
		if len(files) != 6 {
			ignored[dir] = true
			continue
		}
		var sum uint64
		ok := true
		for _, name := range sixCSPFiles {
			if files[name] == nil {
				ok = false
				break
			}
			sum += files[name].UncompressedSize64
		}
		if !ok || sum > maxContainerBytes {
			ignored[dir] = true
			continue
		}
		candidates = append(candidates, cspImportCandidate{dir, files, sum})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	// A certificate or another harmless extra file inside a complete container
	// does not make that directory incomplete or "ignored".
	for _, c := range candidates {
		delete(ignored, c.Name)
	}
	var other []string
	for k := range ignored {
		other = append(other, k)
	}
	sort.Strings(other)
	return candidates, other, nil
}

func randomName() (string, error) {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return ".rt-inspector-stage-" + hex.EncodeToString(bytes[:]), nil
}

// cspImportPreview validates names and counts without reading private key bytes.
func cspImportPreview(zipPath, dest string) (string, error) {
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer z.Close()
	candidates, ignored, err := cspCandidates(z)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", errors.New("нет каталогов с полным набором шести файлов .key")
	}
	var b strings.Builder
	b.WriteString("Из существующего ZIP будут скопированы исходные файлы .key:\r\n\r\n")
	for _, c := range candidates {
		if _, er := os.Stat(filepath.Join(dest, c.Name)); er == nil {
			fmt.Fprintf(&b, "  %s — УЖЕ СУЩЕСТВУЕТ, будет пропущен\r\n", c.Name)
		} else if !os.IsNotExist(er) {
			return "", er
		} else {
			fmt.Fprintf(&b, "  %s — 6 файлов, %.1f КБ\r\n", c.Name, float64(c.Size)/1024)
		}
	}
	if len(ignored) > 0 {
		fmt.Fprintf(&b, "\r\nНеполные и неподдерживаемые каталоги пропускаются: %s\r\n", strings.Join(ignored, ", "))
	}
	fmt.Fprintf(&b, "\r\nКаталог назначения:\r\n%s\r\n", dest)
	b.WriteString("\r\nРеестр, сертификаты и токены не изменяются. ")
	b.WriteString("Эти файлы могут содержать закрытые ключи. Убедитесь, что у вас есть полномочия на их использование.\r\n")
	b.WriteString("Обнаружение папки КриптоПро не гарантирует работоспособность подписи.\r\n\r\nПродолжить?")
	return b.String(), nil
}

// importCSPContainerZIP copies an existing file-container backup into a user's
// Crypto Pro folder, without overwrites and without logging key contents.
func importCSPContainerZIP(zipPath, dest string) (cspImportResult, error) {
	result := cspImportResult{Target: dest}
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return result, err
	}
	defer z.Close()
	candidates, ignored, err := cspCandidates(z)
	if err != nil {
		return result, err
	}
	result.Ignored = ignored
	if len(candidates) == 0 {
		return result, errors.New("в ZIP нет шестифайловых контейнеров CSP")
	}
	if err := os.MkdirAll(dest, 0700); err != nil {
		return result, err
	}
	for _, c := range candidates {
		target := filepath.Join(dest, c.Name)
		if _, er := os.Lstat(target); er == nil {
			result.Skipped = append(result.Skipped, c.Name)
			continue
		} else if !os.IsNotExist(er) {
			return result, er
		}
		stageName, er := randomName()
		if er != nil {
			return result, er
		}
		stage := filepath.Join(dest, stageName)
		if er = os.Mkdir(stage, 0700); er != nil {
			return result, er
		}
		good := false
		copyErr := func() error {
			for _, name := range sixCSPFiles {
				src, er := c.Files[name].Open()
				if er != nil {
					return er
				}
				data, er := io.ReadAll(io.LimitReader(src, 1024*1024+1))
				closeErr := src.Close()
				if er != nil {
					return er
				}
				if closeErr != nil {
					return closeErr
				}
				if uint64(len(data)) != c.Files[name].UncompressedSize64 {
					return fmt.Errorf("ошибка чтения %s/%s", c.Name, name)
				}
				dstName := filepath.Join(stage, name)
				// O_EXCL prevents accidental overwrite even within the private staging dir.
				out, er := os.OpenFile(dstName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if er != nil {
					return er
				}
				_, er = out.Write(data)
				closeErr = out.Close()
				if er != nil {
					return er
				}
				if closeErr != nil {
					return closeErr
				}
				check, er := os.ReadFile(dstName)
				if er != nil {
					return er
				}
				if sha256.Sum256(data) != sha256.Sum256(check) {
					return fmt.Errorf("расхождение SHA256 %s/%s", c.Name, name)
				}
				clear(data)
			}
			if _, er := os.Lstat(target); er == nil {
				return fmt.Errorf("папка %s появилась во время импорта: отмена", c.Name)
			} else if !os.IsNotExist(er) {
				return er
			}
			if er := os.Rename(stage, target); er != nil {
				return er
			}
			good = true
			result.Created = append(result.Created, c.Name)
			return nil
		}()
		if !good {
			_ = os.RemoveAll(stage)
		}
		if copyErr != nil {
			return result, fmt.Errorf("импорт %s: %w", c.Name, copyErr)
		}
	}
	return result, nil
}
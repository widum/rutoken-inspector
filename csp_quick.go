package main

// Quick import of existing CryptoPro FILE CONTAINERS only. This component does
// NOT read private values from tokens, modify the .key files, or modify registry.

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxQuickFile = 1024 * 1024
const maxQuickZIP = 30 * 1024 * 1024

var numberedContainer = regexp.MustCompile(`^[0-9]{1,12}\.000$`)
var unicodeEscape = regexp.MustCompile(`(?i)#U([0-9a-f]{4,6})`)

type quickEntry struct {
	Name string
	Size int64
	Open func() (io.ReadCloser, error)
}
type zipFileReadCloser struct {
	File io.ReadCloser
	ZIP  *zip.ReadCloser
}

func (r zipFileReadCloser) Read(p []byte) (int, error) { return r.File.Read(p) }
func (r zipFileReadCloser) Close() error {
	er := r.File.Close()
	ze := r.ZIP.Close()
	if er != nil {
		return er
	}
	return ze
}
func reopenZIPMember(zipPath, member string) (io.ReadCloser, error) {
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	for _, f := range z.File {
		if f.Name == member {
			rc, er := f.Open()
			if er != nil {
				_ = z.Close()
				return nil, er
			}
			return zipFileReadCloser{File: rc, ZIP: z}, nil
		}
	}
	_ = z.Close()
	return nil, os.ErrNotExist
}

type quickCandidate struct {
	Source   string
	Target   string
	Keys     map[string]quickEntry
	Cert     *quickEntry
	CertName string
	Notes    []string
}
type quickPlan struct {
	Source      string
	Destination string
	Candidates  []quickCandidate
	Ignored     []string
}
type quickResult struct {
	Created      []string
	Messages     []string
	Certificates []string
	Destination  string
}

func quickSourcesZip(zipPath string) (*quickPlan, error) {
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	if len(z.File) > 3000 {
		return nil, errors.New("архив содержит слишком много файлов")
	}
	groups := map[string]map[string]quickEntry{}
	certs := map[string][]quickEntry{}
	names := map[string]bool{}
	var total uint64
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 || strings.Contains(f.Name, "\\") || strings.HasPrefix(f.Name, "/") || path.Clean(f.Name) != f.Name || strings.Contains("/"+f.Name+"/", "/../") {
			return nil, fmt.Errorf("небезопасное имя в архиве: %s", f.Name)
		}
		folded := strings.ToLower(f.Name)
		if names[folded] {
			return nil, fmt.Errorf("дублирующийся путь: %s", f.Name)
		}
		names[folded] = true
		if f.UncompressedSize64 > maxQuickFile {
			return nil, fmt.Errorf("слишком крупный файл %s", f.Name)
		}
		total += f.UncompressedSize64
		if total > maxQuickZIP {
			return nil, errors.New("слишком большой ZIP после распаковки")
		}
		decodedPath := unicodeZIPPath(f)
		if strings.Contains(decodedPath, "\\") || strings.HasPrefix(decodedPath, "/") || path.Clean(decodedPath) != decodedPath {
			return nil, fmt.Errorf("некорректное Unicode имя: %q", decodedPath)
		}
		rel := path.Dir(decodedPath)
		if rel == "." {
			rel = "(корень ZIP)"
		}
		name := path.Base(decodedPath)
		member := f.Name
		entry := quickEntry{Name: name, Size: int64(f.UncompressedSize64), Open: func() (io.ReadCloser, error) { return reopenZIPMember(zipPath, member) }}
		lower := strings.ToLower(name)
		for _, required := range sixCSPFiles {
			if lower == required {
				if groups[rel] == nil {
					groups[rel] = map[string]quickEntry{}
				}
				groups[rel][lower] = entry
				break
			}
		}
		if strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".der") || strings.HasSuffix(lower, ".pem") {
			certs[rel] = append(certs[rel], entry)
		}
	}
	out := &quickPlan{Source: zipPath}
	dirs := make([]string, 0, len(groups))
	for k := range groups {
		dirs = append(dirs, k)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		files := groups[dir]
		if len(files) != 6 {
			out.Ignored = append(out.Ignored, fmt.Sprintf("%s (%d/6 файлов .key)", dir, len(files)))
			continue
		}
		c := quickCandidate{Source: dir, Keys: files}
		if cs := certs[dir]; len(cs) > 0 {
			sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
			c.Cert = &cs[0]
			if len(cs) > 1 {
				c.Notes = append(c.Notes, "несколько сертификатов; выбран первый по имени")
			}
		}
		out.Candidates = append(out.Candidates, c)
	}
	if len(out.Candidates) == 0 {
		return nil, errors.New("не найдено ни одного файлового контейнера с 6 файлами .key; диагностический PKCS#11-дамп не является контейнером")
	}
	return out, nil
}

func quickSourcesDir(source string) (*quickPlan, error) {
	st, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("выберите обычную папку контейнера")
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return nil, err
	}
	files := map[string]quickEntry{}
	var certs []quickEntry
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		if fi.Size() > maxQuickFile {
			return nil, fmt.Errorf("слишком крупный файл: %s", name)
		}
		full := filepath.Join(source, name)
		entry := quickEntry{Name: name, Size: fi.Size(), Open: func() (io.ReadCloser, error) { return os.Open(full) }}
		for _, req := range sixCSPFiles {
			if lower == req {
				files[lower] = entry
			}
		}
		if strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".der") || strings.HasSuffix(lower, ".pem") {
			certs = append(certs, entry)
		}
	}
	if len(files) != 6 {
		return nil, fmt.Errorf("папка содержит %d из 6 файлов .key; файлового контейнера CSP нет", len(files))
	}
	c := quickCandidate{Source: filepath.Base(source), Keys: files}
	if len(certs) > 0 {
		sort.Slice(certs, func(i, j int) bool { return certs[i].Name < certs[j].Name })
		c.Cert = &certs[0]
	}
	return &quickPlan{Source: source, Candidates: []quickCandidate{c}}, nil
}

func planQuickNames(plan *quickPlan, dest string) error {
	if len(plan.Candidates) == 0 {
		return errors.New("нет файловых контейнеров")
	}
	plan.Destination = dest
	allocated := map[string]bool{}
	for i := range plan.Candidates {
		c := &plan.Candidates[i]
		srcName := filepath.Base(c.Source)
		preferred := ""
		if numberedContainer.MatchString(srcName) {
			preferred = srcName
		}
		if preferred != "" && !takenQuick(dest, preferred, allocated) {
			c.Target = preferred
		} else {
			for n := 5000; n <= 9999; n++ {
				candidate := strconv.Itoa(n) + ".000"
				if !takenQuick(dest, candidate, allocated) {
					c.Target = candidate
					break
				}
			}
			if c.Target == "" {
				return errors.New("нет свободных номеров 5000–9999 для контейнеров")
			}
			if preferred != "" {
				c.Notes = append(c.Notes, "исходный номер занят; каталог будет переименован. КриптоПро может не распознать переименованный контейнер")
			}
		}
		allocated[strings.ToLower(c.Target)] = true
		if c.Cert != nil {
			certBytes, err := readQuick(*c.Cert)
			if err != nil {
				return fmt.Errorf("сертификат %s: %w", c.Cert.Name, err)
			}
			if strings.HasSuffix(strings.ToLower(c.Cert.Name), ".pem") {
				certBytes = pemDER(certBytes)
			}
			company := certOrganization(certBytes)
			originalName := decodeLegacyFileName(strings.TrimSuffix(c.Cert.Name, filepath.Ext(c.Cert.Name)))
			if company == "" || normalizedOrg(originalName) == normalizedOrg(company) {
				company = originalName
			} else {
				company = strings.ReplaceAll(company, `"`, "")
			}
			company = safeCertName(company)
			if company == "" {
				company = "Сертификат"
			}
			c.CertName = company + ".cer"
			if !looksDERCertificate(certBytes) {
				c.CertName = ""
				c.Notes = append(c.Notes, "сертификат не распознан как DER X.509; сохранение сертификата пропущено")
			}
		}
	}
	return nil
}
func takenQuick(dest, name string, allocated map[string]bool) bool {
	if allocated[strings.ToLower(name)] {
		return true
	}
	_, err := os.Lstat(filepath.Join(dest, name))
	return err == nil || !os.IsNotExist(err)
}
func quickPreview(plan *quickPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Источник: %s\r\nКаталог CSP 5.x: %s\r\n\r\n", plan.Source, plan.Destination)
	for _, c := range plan.Candidates {
		fmt.Fprintf(&b, "%s → %s  [6 исходных .key без изменений]\r\n", c.Source, c.Target)
		if c.CertName != "" {
			fmt.Fprintf(&b, "  Сертификат: %s\r\n", c.CertName)
		} else {
			b.WriteString("  Сертификат не найден или не распознан\r\n")
		}
		for _, note := range c.Notes {
			fmt.Fprintf(&b, "  Внимание: %s\r\n", note)
		}
	}
	if len(plan.Ignored) > 0 {
		fmt.Fprintf(&b, "\r\nПропущены: %s\r\n", strings.Join(plan.Ignored, ", "))
	}
	b.WriteString("\r\nЗакрытые ключи берутся ТОЛЬКО из уже существующих файлов .key.\r\n")
	b.WriteString("Связь сертификата с закрытым ключом НЕ проверялась и НЕ создаётся автоматически.\r\n")
	b.WriteString("Существующие папки и реестр не изменяются. Продолжить импорт?")
	return b.String()
}
func readQuick(e quickEntry) ([]byte, error) {
	if e.Size <= 0 || e.Size > maxQuickFile {
		return nil, errors.New("недопустимый размер файла")
	}
	r, err := e.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxQuickFile+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != e.Size {
		return nil, errors.New("длина файла отличается от заявленной")
	}
	return b, nil
}
func installQuick(plan *quickPlan) (quickResult, error) {
	result := quickResult{Destination: plan.Destination}
	if err := os.MkdirAll(plan.Destination, 0700); err != nil {
		return result, err
	}
	for _, c := range plan.Candidates {
		target := filepath.Join(plan.Destination, c.Target)
		if takenQuick(plan.Destination, c.Target, nil) {
			return result, fmt.Errorf("назначение %s уже существует: ничего не перезаписано", target)
		}
		stage, err := os.MkdirTemp(plan.Destination, ".inspector-tmp-")
		if err != nil {
			return result, err
		}
		committed := false
		err = func() error {
			for _, req := range sixCSPFiles {
				src, ok := c.Keys[req]
				if !ok {
					return fmt.Errorf("отсутствует %s", req)
				}
				data, er := readQuick(src)
				if er != nil {
					return er
				}
				full := filepath.Join(stage, req)
				if er = writeQuick(full, data); er != nil {
					clear(data)
					return er
				}
				check, er := os.ReadFile(full)
				if er != nil {
					clear(data)
					return er
				}
				if sha256.Sum256(check) != sha256.Sum256(data) {
					clear(data)
					return fmt.Errorf("ошибка контрольной суммы %s", req)
				}
				clear(data)
				clear(check)
			}
			if c.Cert != nil && c.CertName != "" {
				data, er := readQuick(*c.Cert)
				if er != nil {
					return er
				}
				if strings.HasSuffix(strings.ToLower(c.Cert.Name), ".pem") {
					data = pemDER(data)
				}
				if !looksDERCertificate(data) {
					return errors.New("сертификат не является DER X.509")
				}
				if er = writeQuick(filepath.Join(stage, c.CertName), data); er != nil {
					return er
				}
			}
			if takenQuick(plan.Destination, c.Target, nil) {
				return fmt.Errorf("папка %s появилась при импорте", c.Target)
			}
			if er := os.Rename(stage, target); er != nil {
				return er
			}
			committed = true
			return nil
		}()
		if !committed {
			_ = os.RemoveAll(stage)
		}
		if err != nil {
			return result, fmt.Errorf("контейнер %s: %w", c.Source, err)
		}
		result.Created = append(result.Created, c.Target)
		result.Messages = append(result.Messages, fmt.Sprintf("%s → %s", c.Source, c.Target))
		if c.CertName != "" {
			result.Certificates = append(result.Certificates, fmt.Sprintf("%s\\%s", c.Target, c.CertName))
		}
	}
	return result, nil
}
func writeQuick(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func decodeLegacyFileName(s string) string {
	return unicodeEscape.ReplaceAllStringFunc(s, func(m string) string {
		hexValue := m[2:]
		v, err := strconv.ParseInt(hexValue, 16, 32)
		if err != nil || v < 32 || !utf8.ValidRune(rune(v)) {
			return m
		}
		return string(rune(v))
	})
}
func normalizedOrg(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func safeCertName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`<>:"/\\|?*`, r) || unicode.IsControl(r) {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
		if b.Len() > 160 {
			break
		}
	}
	s = strings.TrimRight(strings.TrimSpace(b.String()), ". ")
	if s == "" || s == "." || s == ".." {
		return ""
	}
	return s
}
func looksDERCertificate(b []byte) bool {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	return err == nil && len(rest) == 0 && v.Class == 0 && v.Tag == asn1.TagSequence && len(v.Bytes) > 20
}
func pemDER(b []byte) []byte {
	// Helper supports PEM certificates without depending on GOST decoding.
	p, _ := pemDecodeCert(b)
	if len(p) > 0 {
		return p
	}
	return b
}
func certOrganization(der []byte) string {
	var outer, tbs asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || outer.Tag != 16 {
		return ""
	}
	_, err = asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil || tbs.Tag != 16 {
		return ""
	}
	fields := tbs.Bytes
	var field asn1.RawValue
	if _, err = asn1.Unmarshal(fields, &field); err != nil {
		return ""
	}
	if field.Class == 2 && field.Tag == 0 {
		fields, _ = asn1.Unmarshal(fields, &field)
	}
	// serialNumber, signature, issuer, validity, subject
	for n := 0; n < 5; n++ {
		rest, er := asn1.Unmarshal(fields, &field)
		if er != nil {
			return ""
		}
		fields = rest
	}
	var dn pkix.RDNSequence
	rest, err = asn1.Unmarshal(field.FullBytes, &dn)
	if err != nil || len(rest) != 0 {
		return ""
	}
	var org, cn string
	for _, set := range dn {
		for _, attr := range set {
			val, ok := attr.Value.(string)
			if !ok {
				continue
			}
			switch attr.Type.String() {
			case "2.5.4.10":
				if org == "" {
					org = val
				}
			case "2.5.4.3":
				if cn == "" {
					cn = val
				}
			}
		}
	}
	if org != "" {
		return org
	}
	return cn
}
func quickSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func quickRandomName() (string, error) {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	return hex.EncodeToString(buf), err
}
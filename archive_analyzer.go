package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// This checks whether an archive has the FILE STRUCTURE expected by a
// legacy CryptoPro CSP directory container. It does NOT authenticate private
// keys, extract/import credentials, alter Windows registry, or claim that a
// matching set will sign successfully. In particular, PKCS#11 metadata or
// a certificate alone are not sufficient to sign.
var cspFiles = []string{"header.key", "masks.key", "masks2.key", "name.key", "primary.key", "primary2.key"}

type cspCandidate struct {
	files map[string]*zip.File
	other []string
}

func analyzeZipText(filename string) (string, string) {
	z, err := zip.OpenReader(filename)
	if err != nil {
		return "", "Ошибка ZIP: " + err.Error()
	}
	defer z.Close()
	if len(z.File) > 3000 {
		return "", "Слишком много файлов в архиве"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Архив: %s\r\n", filepath.Base(filename))
	b.WriteString("ПРОВЕРКА ПРИГОДНОСТИ ДЛЯ КРИПТОПРО CSP 5.x\r\n\r\n")
	groups := map[string]*cspCandidate{}
	var total uint64
	files := 0
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		files++
		total += f.UncompressedSize64
		if total > 64*1024*1024 {
			return "", "Суммарный размер файлов превышает лимит 64 МБ"
		}
		// ZIP file names always use slash, even on Windows.
		normalized := strings.ReplaceAll(unicodeZIPPath(f), "\\", "/")
		if strings.HasPrefix(normalized, "/") || strings.Contains("/"+normalized+"/", "/../") || strings.HasPrefix(normalized, "../") {
			return "", "Обнаружен небезопасный путь внутри ZIP"
		}
		dir := path.Dir(normalized)
		if dir == "." {
			dir = "(корень ZIP)"
		}
		base := strings.ToLower(path.Base(normalized))
		grp := groups[dir]
		if grp == nil {
			grp = &cspCandidate{files: map[string]*zip.File{}}
			groups[dir] = grp
		}
		isKey := false
		for _, s := range cspFiles {
			if base == s {
				isKey = true
				break
			}
		}
		if isKey {
			grp.files[base] = f
		} else {
			grp.other = append(grp.other, base)
		}
	}
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "Обнаружено файлов: %d. Каталогов: %d.\r\n\r\n", files, len(groups))
	found := 0
	for _, n := range names {
		grp := groups[n]
		var missing []string
		for _, s := range cspFiles {
			if grp.files[s] == nil {
				missing = append(missing, s)
			}
		}
		count := len(grp.files)
		fmt.Fprintf(&b, "КАТАЛОГ: %s\r\n", n)
		if count == len(cspFiles) {
			found++
			b.WriteString("  ФОРМАТ: полный набор 6 имён *.key (кандидат на файловый контейнер CSP)\r\n")
			b.WriteString("  СТАТУС: структуру можно передать на проверку штатному КриптоПро.\r\n")
			b.WriteString("  ВАЖНО: по именам файлов нельзя подтвердить наличие действующего ключа и его работоспособность.\r\n")
		} else if count > 0 {
			fmt.Fprintf(&b, "  ФОРМАТ: неполный набор ключевых файлов (%d/6)\r\n", count)
			b.WriteString("  Отсутствуют: " + strings.Join(missing, ", ") + "\r\n")
		} else {
			b.WriteString("  ФОРМАТ: нет файлового контейнера КриптоПро (0/6 файлов .key).\r\n")
		}
		for _, s := range cspFiles {
			if grp.files[s] != nil {
				fmt.Fprintf(&b, "    %-13s %d байт (содержимое не читается программой)\r\n", s, grp.files[s].UncompressedSize64)
			}
		}
		sort.Strings(grp.other)
		for _, s := range grp.other {
			fmt.Fprintf(&b, "    прочее: %s\r\n", s)
		}
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "ИТОГ: каталогов с шестью файлами .key: %d\r\n", found)
	b.WriteString("Файл CER/PEM и PKCS#11-дамп сами по себе не обеспечивают подписания.\r\n")
	b.WriteString("Связь сертификата с контейнером в реестре — указатель на ключ, а не сам ключ.\r\n")
	b.WriteString("Эта проверка НЕ извлекает, НЕ копирует и НЕ импортирует закрытые ключи; не меняет реестр.\r\n")
	b.WriteString("\r\nПРОВЕРКА ЦЕЛОСТНОСТИ ПУБЛИЧНЫХ ФАЙЛОВ:\r\n")
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		displayName := unicodeZIPPath(f)
		ext := strings.ToLower(path.Ext(displayName))
		if ext != ".cer" && ext != ".pem" && path.Base(displayName) != "manifest.json" {
			continue
		}
		if f.UncompressedSize64 > 4*1024*1024 {
			fmt.Fprintf(&b, "%s: файл пропущен (>4 МБ)\r\n", displayName)
			continue
		}
		stream, e := f.Open()
		if e != nil {
			continue
		}
		bytes, e := io.ReadAll(io.LimitReader(stream, 4*1024*1024+1))
		_ = stream.Close()
		if e != nil {
			continue
		}
		hash := sha256.Sum256(bytes)
		fmt.Fprintf(&b, "%s: SHA256=%s\r\n", displayName, strings.ToUpper(hex.EncodeToString(hash[:])))
	}
	return b.String(), ""
}
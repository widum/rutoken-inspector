package main

// Export a real directory with readable public data only. This is a usability
// feature for a manual CryptoPro folder detection experiment, NOT a key clone.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func cspTestFolderName(_ *scanReport) string {
	return "TOKEN.000"
}

func exportPublicCSPTestFolder(root string, r *scanReport) (string, error) {
	if r == nil {
		return "", fmt.Errorf("сначала выполните сканирование")
	}
	if root == "" {
		return "", fmt.Errorf("не указана папка экспорта")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	destination, err := os.MkdirTemp(root, "Rutoken_CSP_Test_")
	if err != nil {
		return "", err
	}
	// Never modify existing `%LOCALAPPDATA%/Crypto Pro` automatically.
	folder := filepath.Join(destination, cspTestFolderName(r))
	if err = os.Mkdir(folder, 0700); err != nil {
		return "", err
	}
	fail := func(err error) (string, error) { _ = os.RemoveAll(destination); return "", err }
	write := func(name string, data []byte) error {
		if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
			return fmt.Errorf("опасное имя %q", name)
		}
		path := filepath.Join(folder, name)
		return os.WriteFile(path, data, 0600)
	}
	meta, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err = write("manifest.json", meta); err != nil {
		return fail(err)
	}
	var sums strings.Builder
	for i, o := range r.Objects {
		if o.Attributes["CKA_PRIVATE"] == true || o.Class == "Закрытый ключ" || o.Class == "Секретный ключ" {
			continue
		}
		var name string
		var b []byte
		switch o.Class {
		case "Сертификат":
			if len(o.Cert) == 0 {
				continue
			}
			name = fmt.Sprintf("%03d_certificate.cer", i)
			b = o.Cert
			if len(b) != o.CertLength || upperSHA(b) != o.CertSHA256 {
				return fail(fmt.Errorf("сертификат %d: ошибка контрольной суммы", i))
			}
		case "Открытый ключ", "Объект данных":
			if o.DataRead != "ok" {
				continue
			}
			kind := "data"
			if o.Class == "Открытый ключ" {
				kind = "public_key"
			}
			name = fmt.Sprintf("%03d_%s.bin", i, kind)
			b = o.PublicData
			if len(b) != o.DataLength || upperSHA(b) != o.DataSHA256 {
				return fail(fmt.Errorf("объект %d: ошибка контрольной суммы", i))
			}
		default:
			continue
		}
		if len(b) > 1024*1024 {
			return fail(fmt.Errorf("публичный объект %d больше 1 МиБ", i))
		}
		if err = write(name, b); err != nil {
			return fail(err)
		}
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\r\n", strings.ToUpper(hex.EncodeToString(h[:])), name)
	}
	if err = write("SHA256SUMS.txt", []byte(sums.String())); err != nil {
		return fail(err)
	}
	readme := "ПРОВЕРОЧНАЯ ПАПКА ДЛЯ CRYPTOPRO CSP 5.x\r\n\r\n" +
		"Это только тестовая структура файлов *.000, которая\r\n" +
		"НЕ содержит закрытого ключа и не является рабочим контейнером.\r\n" +
		"Файлы созданы из разрешённых публичных PKCS#11 объектов.\r\n" +
		"Нет ни одного штатного файла header.key / masks.key / primary.key и пр.\r\n" +
		"Ожидаемый результат: CryptoPro CSP НЕ покажет её как действующий ключ.\r\n" +
		"Переименование файлов и привязка сертификата в реестре ключ не создаёт.\r\n\r\n" +
		"Для ручного теста скопируйте вложенную папку *.000 в:\r\n" +
		"%LOCALAPPDATA%\\Crypto Pro\\\r\n" +
		"Не заменяйте уже существующую папку с тем же именем.\r\n" +
		"Проверять: КриптоПро CSP → Сервис → Протестировать → Обзор.\r\n"
	if err = os.WriteFile(filepath.Join(destination, "ПРОЧИТАТЬ_ПЕРЕД_КОПИРОВАНИЕМ.txt"), []byte(readme), 0600); err != nil {
		return fail(err)
	}
	return folder, nil
}
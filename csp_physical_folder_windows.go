//go:build windows

package main

// Checks the *filesystem outcome* of a vendor-authorized CSP copy. It never
// opens private-key bytes or fabricates the six key files.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func snapshotPhysicalCSPFolders() (map[string]string, error) {
	root, err := cspDestination()
	if err != nil {
		return nil, err
	}
	folders := make(map[string]string)
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return folders, nil
	}
	if err != nil {
		return nil, err
	}
	for _, item := range entries {
		if !item.IsDir() || item.Type()&os.ModeSymlink != 0 || !numberedContainer.MatchString(item.Name()) {
			continue
		}
		folders[strings.ToLower(item.Name())] = filepath.Join(root, item.Name())
	}
	return folders, nil
}

// Only verifies that the expected file names exist and are nonempty.  This is
// NOT proof that a cryptographic signature will work; CSP must verify that.
func checkPhysicalCSPNames(folder string) error {
	fi, err := os.Lstat(folder)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("не обычная папка контейнера")
	}
	for _, name := range sixCSPFiles {
		fi, err := os.Lstat(filepath.Join(folder, name))
		if err != nil {
			return fmt.Errorf("отсутствует %s: %w", name, err)
		}
		if !fi.Mode().IsRegular() || fi.Size() <= 0 {
			return fmt.Errorf("файл %s некорректный (размер %d)", name, fi.Size())
		}
	}
	return nil
}

func newPhysicalCSPFolders(before, after map[string]string) []string {
	var result []string
	for name, folder := range after {
		if _, ok := before[name]; !ok {
			result = append(result, folder)
		}
	}
	sort.Strings(result)
	return result
}

func newCSPFolderOutcome(before map[string]string, beforeErr error) string {
	after, afterErr := snapshotPhysicalCSPFolders()
	if beforeErr != nil || afterErr != nil {
		return fmt.Sprintf("Проверка фактической папки .000 не завершена. До: %v; после: %v.\r\n", beforeErr, afterErr)
	}
	created := newPhysicalCSPFolders(before, after)
	if len(created) == 0 {
		return "Новую папку .000 в %LOCALAPPDATA%\\Crypto Pro определить не удалось. Проверьте через Проводник; не создавайте вручную фиктивные .key.\r\n"
	}
	if len(created) != 1 {
		return fmt.Sprintf("Обнаружено %d новых папок .000; однозначно сопоставить их с операцией нельзя.\r\n", len(created))
	}
	folder := created[0]
	if err := checkPhysicalCSPNames(folder); err != nil {
		return fmt.Sprintf("Создан каталог %s, но он НЕ подтверждён как полный файловый контейнер: %v.\r\n", folder, err)
	}
	return fmt.Sprintf("Папка контейнера создана КриптоПро: %s\r\nФайлы .key: 6/6. Для проверки подписи отключите физический токен.\r\n", folder)
}
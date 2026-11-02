//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Windows DRIVE_REMOVABLE is the only filesystem-backed source accepted.
// Smart-card readers (including Rutoken S) cannot be mapped to a drive here.
func mountedRemovableRoots() []string {
	var result []string
	k := syscall.NewLazyDLL("kernel32.dll")
	mask, _, _ := k.NewProc("GetLogicalDrives").Call()
	kind := k.NewProc("GetDriveTypeW")
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", rune('A'+i))
		t, _, _ := kind.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(root))))
		if t == 2 {
			result = append(result, root)
		}
	}
	return result
}

func (a *window) copyFromAccessibleMedia() {
	if a.busy {
		alert("Операция выполняется", "Завершите текущую операцию.", mbIconInfo)
		return
	}
	roots := mountedRemovableRoots()
	if len(roots) == 0 {
		alert("Нет файлового USB-носителя", "Windows не обнаружила ни одного съёмного диска с доступной файловой системой. Рутокен S использует интерфейс смарт-карты, а не файлового USB-диска: эта функция не извлекает из него защищённые ключи.", mbIconInfo)
		return
	}
	plan, err := discoverAccessibleContainers(roots)
	if err != nil {
		alert("Контейнер не найден", err.Error(), mbIconInfo)
		return
	}
	dest, err := cspDestination()
	if err != nil {
		alert("Crypto Pro", err.Error(), mbIconError)
		return
	}
	if err := planQuickNames(plan, dest); err != nil {
		alert("Ошибка", err.Error(), mbIconError)
		return
	}
	// Show exactly one confirmation: performQuickImport already previews all
	// source and destination paths and verifies existing folders.
	a.performQuickImport(plan)
}
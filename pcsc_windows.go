//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Enumerate Windows Smart Card readers independently of vendor PKCS#11 DLLs.
// This does not transmit APDUs, require a PIN, or change token contents.
func listPCSCReaders() ([]string, string) {
	dll := syscall.NewLazyDLL("winscard.dll")
	establish := dll.NewProc("SCardEstablishContext")
	release := dll.NewProc("SCardReleaseContext")
	list := dll.NewProc("SCardListReadersW")
	var context uintptr
	rc, _, _ := establish.Call(2, 0, 0, uintptr(unsafe.Pointer(&context))) // SCARD_SCOPE_SYSTEM
	if uint32(rc) != 0 {
		return nil, fmt.Sprintf("SCardEstablishContext=0x%08X", uint32(rc))
	}
	defer release.Call(context)
	var n uint32
	rc, _, _ = list.Call(context, 0, 0, uintptr(unsafe.Pointer(&n)))
	if uint32(rc) == 0x8010002E {
		return []string{}, ""
	} // no readers
	if uint32(rc) != 0 {
		return nil, fmt.Sprintf("SCardListReaders(count)=0x%08X", uint32(rc))
	}
	if n == 0 || n > 32768 {
		return nil, "Недопустимый размер списка PC/SC"
	}
	names := make([]uint16, n)
	rc, _, _ = list.Call(context, 0, uintptr(unsafe.Pointer(&names[0])), uintptr(unsafe.Pointer(&n)))
	if uint32(rc) != 0 {
		return nil, fmt.Sprintf("SCardListReaders(data)=0x%08X", uint32(rc))
	}
	if n > uint32(len(names)) {
		return nil, "Изменился размер списка PC/SC"
	}
	var out []string
	start := 0
	for i := 0; i < int(n); i++ {
		if names[i] == 0 {
			if i == start {
				break
			}
			out = append(out, syscall.UTF16ToString(names[start:i]))
			start = i + 1
		}
	}
	return out, ""
}
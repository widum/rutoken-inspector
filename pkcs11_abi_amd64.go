// This file intentionally has no Windows-specific dependencies.
// Its ABI marshaling can be tested on Linux before cross-compiling the Windows app.
package main

import "encoding/binary"

// CK_FUNCTION_LIST begins with CK_VERSION (2 bytes), then pointers IMMEDIATELY.
// The old version wrongly skipped 6 bytes of padding, calling invalid addresses.
const packedFunctionListHeader = 2

// PKCS#11 CK_ATTRIBUTE in Windows x64 has *packed*, 16-byte layout:
// Type@0(4), pValue@4(8), ulValueLen@12(4).
// Using a Go struct with uintptr would silently insert 4 bytes of padding.
const packedAttributeSize = 16

func makeCKAttribute(attrType uint32, ptr uintptr, valueLen uint32) [packedAttributeSize]byte {
	var a [packedAttributeSize]byte
	binary.LittleEndian.PutUint32(a[0:4], attrType)
	binary.LittleEndian.PutUint64(a[4:12], uint64(ptr))
	binary.LittleEndian.PutUint32(a[12:16], valueLen)
	return a
}
func ckAttributeLen(a *[packedAttributeSize]byte) uint32 {
	return binary.LittleEndian.Uint32(a[12:16])
}
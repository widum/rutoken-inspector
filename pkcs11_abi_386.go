//go:build 386

// PKCS#11 Windows 32-bit uses 4-byte pointers / CK_ULONG.
package main

import "encoding/binary"

const packedFunctionListHeader = 2
const packedAttributeSize = 12

func makeCKAttribute(attrType uint32, ptr uintptr, valueLen uint32) [packedAttributeSize]byte {
	var a [packedAttributeSize]byte
	binary.LittleEndian.PutUint32(a[0:4], attrType)
	binary.LittleEndian.PutUint32(a[4:8], uint32(ptr))
	binary.LittleEndian.PutUint32(a[8:12], valueLen)
	return a
}
func ckAttributeLen(a *[packedAttributeSize]byte) uint32 {
	return binary.LittleEndian.Uint32(a[8:12])
}
package main

import (
	"encoding/binary"
	"strconv"
	"testing"
)

func TestCKFunctionListPackedOffset(t *testing.T) {
	if packedFunctionListHeader != 2 {
		t.Fatalf("OASIS CK_FUNCTION_LIST must begin with 2-byte CK_VERSION, got %d", packedFunctionListHeader)
	}
}

func TestCKAttributePackedWindows(t *testing.T) {
	expectedSize := 16
	if strconv.IntSize == 32 {
		expectedSize = 12
	}
	if packedAttributeSize != expectedSize {
		t.Fatalf("CK_ATTRIBUTE size=%d, expected %d", packedAttributeSize, expectedSize)
	}
	ptr := uint64(0x1122334455667788)
	if strconv.IntSize == 32 {
		ptr = 0x55667788
	}
	a := makeCKAttribute(0x01020304, uintptr(ptr), 0xDEADBEEF)
	if got := binary.LittleEndian.Uint32(a[:4]); got != 0x01020304 {
		t.Fatalf("type=%x", got)
	}
	if strconv.IntSize == 32 {
		if got := binary.LittleEndian.Uint32(a[4:8]); got != uint32(ptr) {
			t.Fatalf("pointer=%x", got)
		}
	} else {
		if got := binary.LittleEndian.Uint64(a[4:12]); got != ptr {
			t.Fatalf("pointer=%x", got)
		}
	}
	if got := ckAttributeLen(&a); got != 0xDEADBEEF {
		t.Fatalf("length=%x", got)
	}
}
package main

import (
	"archive/zip"
	"encoding/binary"
	"hash/crc32"
	"unicode/utf8"
)

// ZIPs created by some Windows archivers store CP866 names plus a Unicode Path
// (0x7075) extra field. Use the validated UTF-8 path for display and CER names.
func unicodeZIPPath(f *zip.File) string {
	raw := f.Name
	extra := f.Extra
	for len(extra) >= 4 {
		typ := binary.LittleEndian.Uint16(extra[:2])
		n := int(binary.LittleEndian.Uint16(extra[2:4]))
		extra = extra[4:]
		if n > len(extra) {
			break
		}
		payload := extra[:n]
		extra = extra[n:]
		if typ == 0x7075 && len(payload) >= 5 && payload[0] == 1 && binary.LittleEndian.Uint32(payload[1:5]) == crc32.ChecksumIEEE([]byte(raw)) && utf8.Valid(payload[5:]) {
			return string(payload[5:])
		}
	}
	return raw
}
package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
)

func unicodePathExtra(raw []byte, name string) []byte {
	payload := make([]byte, 5+len(name))
	payload[0] = 1
	binary.LittleEndian.PutUint32(payload[1:5], crc32.ChecksumIEEE(raw))
	copy(payload[5:], name)
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint16(0x7075))
	_ = binary.Write(&b, binary.LittleEndian, uint16(len(payload)))
	b.Write(payload)
	return b.Bytes()
}
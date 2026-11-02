package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// A 64-bit Windows PKCS#11 2.40 client. CK_ULONG is 32-bit on Windows (LLP64).
// PKCS#11 structures are packed to 1 byte on Windows (OASIS pkcs11.h).
// Only read-only calls are exposed; CKA_VALUE is read for public certificates alone.
const (
	ckrOK                  = 0
	ckrAlreadyInitialized  = 0x191
	ckfSerialSession       = 4
	ckuUser                = 1
	ckrUserAlreadyLoggedIn = 0x00000100
	ckaClass               = 0x0000
	ckaLabel               = 0x0003
	ckaID                  = 0x0102
	ckaValue               = 0x0011
	ckaApplication         = 0x0010
	ckaObjectID            = 0x0012
	ckaCertificateType     = 0x0080
	ckaIssuer              = 0x0081
	ckaSerialNumber        = 0x0082
	ckaSubject             = 0x0101
	ckaECParams            = 0x0180
	ckaECPoint             = 0x0181
	ckaEncrypt             = 0x0104
	ckaDecrypt             = 0x0105
	ckaWrap                = 0x0106
	ckaUnwrap              = 0x0107
	ckaDerive              = 0x010C
	ckaPrivate             = 0x0002
	ckaKeyType             = 0x0100
	ckaSensitive           = 0x0103
	ckaExtractable         = 0x0162
	ckaNeverExtractable    = 0x0164
	ckaAlwaysSensitive     = 0x0165
	ckaSign                = 0x0108
	ckaVerify              = 0x010A
	ckaToken               = 0x0001
	ckaModifiable          = 0x0170
)

// Indexes into CK_FUNCTION_LIST (after the packed two-byte CK_VERSION).
const (
	fnInitialize        = 0
	fnFinalize          = 1
	fnGetSlotList       = 4
	fnGetTokenInfo      = 6
	fnOpenSession       = 12
	fnCloseSession      = 13
	fnLogin             = 18
	fnLogout            = 19
	fnGetAttributeValue = 24
	fnFindObjectsInit   = 26
	fnFindObjects       = 27
	fnFindObjectsFinal  = 28
)

type deviceInfo struct {
	Slot         uint32 `json:"slot"`
	Label        string `json:"label"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	Manufacturer string `json:"manufacturer"`
	Library      string `json:"library,omitempty"`
}
type objectInfo struct {
	Class      string         `json:"class"`
	Label      string         `json:"label"`
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
	Export     string         `json:"export,omitempty"`
	CertSHA256 string         `json:"certificate_sha256,omitempty"`
	CertLength int            `json:"certificate_length,omitempty"`
	DataSHA256 string         `json:"public_value_sha256,omitempty"`
	DataLength int            `json:"public_value_length,omitempty"`
	DataRead   string         `json:"public_value_status,omitempty"`
	Cert       []byte         `json:"-"`
	PublicData []byte         `json:"-"`
}
type scanReport struct {
	Tool          string       `json:"tool"`
	Mode          string       `json:"mode"`
	Authenticated bool         `json:"authenticated"`
	ScanAtUTC     string       `json:"scan_at_utc"`
	Token         deviceInfo   `json:"token"`
	Objects       []objectInfo `json:"objects"`
	Errors        []string     `json:"errors"`
}

type pkcs struct {
	dll        *syscall.DLL
	funcs      uintptr
	doFinalize bool
}

func (p *pkcs) call(index int, args ...uintptr) uint32 {
	if index < 0 || index > 68 || p.funcs == 0 {
		return 0x00000054 // CKR_FUNCTION_NOT_SUPPORTED
	}
	f := *(*uintptr)(unsafe.Pointer(p.funcs + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	if f < 0x10000 {
		return 0x00000054 // Invalid or missing entry; never call a null pointer
	}
	rv, _, _ := syscall.SyscallN(f, args...)
	return uint32(rv)
}
func errCK(fn string, code uint32) error {
	return fmt.Errorf("%s: PKCS#11 ошибка 0x%08X", fn, code)
}
func openPKCS(path string) (*pkcs, error) {
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить PKCS#11 DLL %s: %w", path, err)
	}
	proc, err := dll.FindProc("C_GetFunctionList")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("в библиотеке нет C_GetFunctionList: %w", err)
	}
	appendLog("PKCS11: found C_GetFunctionList export")
	var list uintptr
	rv, _, _ := proc.Call(uintptr(unsafe.Pointer(&list)))
	if uint32(rv) != ckrOK || list == 0 {
		dll.Release()
		return nil, errors.New("не удалось получить список PKCS#11 функций")
	}
	// A packed CK_FUNCTION_LIST: two version bytes, NO alignment padding.
	version := *(*[2]byte)(unsafe.Pointer(list))
	if version[0] == 0 || version[0] > 3 {
		dll.Release()
		return nil, fmt.Errorf("неожиданная версия PKCS#11: %d.%d", version[0], version[1])
	}
	p := &pkcs{dll: dll, funcs: list + packedFunctionListHeader}
	appendLog(fmt.Sprintf("PKCS11 ABI: packed CK_FUNCTION_LIST header=%d, CK_ATTRIBUTE size=%d, version=%d.%d", packedFunctionListHeader, packedAttributeSize, version[0], version[1]))
	appendLog("PKCS11: entering C_Initialize")
	ret := p.call(fnInitialize, 0)
	appendLog(fmt.Sprintf("PKCS11: C_Initialize returned 0x%08X", ret))
	if ret != ckrOK && ret != ckrAlreadyInitialized {
		dll.Release()
		return nil, errCK("C_Initialize", ret)
	}
	p.doFinalize = ret == ckrOK
	runtime.KeepAlive(&list)
	return p, nil
}
func (p *pkcs) close() {
	if p.doFinalize {
		p.call(fnFinalize, 0)
	}
	p.dll.Release()
}
func trimField(b []byte) string { return strings.Trim(string(b), " \x00\t\r\n") }
func (p *pkcs) slots() ([]deviceInfo, error) {
	var count uint32
	appendLog("PKCS11: entering C_GetSlotList (count)")
	if rv := p.call(fnGetSlotList, 1, 0, uintptr(unsafe.Pointer(&count))); rv != ckrOK {
		return nil, errCK("C_GetSlotList", rv)
	}
	if count > 1000 {
		return nil, errors.New("слишком много слотов")
	}
	if count == 0 {
		return []deviceInfo{}, nil
	}
	appendLog(fmt.Sprintf("PKCS11: C_GetSlotList reported %d populated slots", count))
	ids := make([]uint32, count)
	maxCount := count
	appendLog("PKCS11: entering C_GetSlotList (IDs)")
	rv := p.call(fnGetSlotList, 1, uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(ids)
	if rv != ckrOK {
		return nil, errCK("C_GetSlotList", rv)
	}
	if count > maxCount {
		return nil, errors.New("число слотов изменилось во время чтения; повторите поиск")
	}
	appendLog(fmt.Sprintf("PKCS11: C_GetSlotList completed with %d slots", count))
	results := make([]deviceInfo, 0, count)
	for _, id := range ids[:count] {
		// CK_TOKEN_INFO begins with fixed-size text fields and is at least 160 bytes.
		var info [256]byte
		rv = p.call(fnGetTokenInfo, uintptr(id), uintptr(unsafe.Pointer(&info[0])))
		runtime.KeepAlive(info)
		if rv != ckrOK {
			continue
		}
		results = append(results, deviceInfo{Slot: id, Label: trimField(info[0:32]), Manufacturer: trimField(info[32:64]), Model: trimField(info[64:80]), Serial: trimField(info[80:96])})
	}
	return results, nil
}
func (p *pkcs) attr(handle uint32, obj uint32, attrType uint32, maxLen int) ([]byte, bool) {
	a := makeCKAttribute(attrType, 0, 0)
	rv := p.call(fnGetAttributeValue, uintptr(handle), uintptr(obj), uintptr(unsafe.Pointer(&a[0])), 1)
	length := ckAttributeLen(&a)
	if rv != ckrOK || length == 0xFFFFFFFF || length > uint32(maxLen) {
		return nil, false
	}
	if length == 0 {
		return []byte{}, true
	}
	value := make([]byte, length)
	a = makeCKAttribute(attrType, uintptr(unsafe.Pointer(&value[0])), length)
	rv = p.call(fnGetAttributeValue, uintptr(handle), uintptr(obj), uintptr(unsafe.Pointer(&a[0])), 1)
	runtime.KeepAlive(value)
	resultLen := ckAttributeLen(&a)
	if rv != ckrOK || resultLen > uint32(len(value)) {
		return nil, false
	}
	return value[:resultLen], true
}
func attrBool(b []byte, ok bool) any {
	if !ok || len(b) == 0 {
		return nil
	}
	return b[0] != 0
}
func (p *pkcs) scan(dev deviceInfo, pin []byte) (*scanReport, error) {
	mode := "read-only; without PIN"
	if len(pin) > 0 {
		mode = "read-only; authenticated user"
	}
	report := &scanReport{Tool: "Rutoken Inspector 3 Standalone", Mode: mode, ScanAtUTC: time.Now().UTC().Format(time.RFC3339), Token: dev, Objects: []objectInfo{}, Errors: []string{}}
	var session uint32
	rv := p.call(fnOpenSession, uintptr(dev.Slot), ckfSerialSession, 0, 0, uintptr(unsafe.Pointer(&session)))
	if rv != ckrOK {
		return nil, errCK("C_OpenSession", rv)
	}
	defer p.call(fnCloseSession, uintptr(session))
	if len(pin) > 0 {
		appendLog("PKCS11: user authentication requested; PIN content not logged")
		rv = p.call(fnLogin, uintptr(session), uintptr(ckuUser), uintptr(unsafe.Pointer(&pin[0])), uintptr(len(pin)))
		runtime.KeepAlive(pin)
		if rv != ckrOK && rv != ckrUserAlreadyLoggedIn {
			if rv == 0xA0 {
				return nil, errors.New("Неверный PIN пользователя: CKR_PIN_INCORRECT (0x000000A0). Не перебирайте варианты: число попыток ограничено")
			}
			if rv == 0xA4 {
				return nil, errors.New("PIN заблокирован: CKR_PIN_LOCKED (0x000000A4). Обратитесь к администратору ключа")
			}
			return nil, errCK("C_Login", rv)
		}
		report.Authenticated = true
		if rv == ckrOK {
			defer p.call(fnLogout, uintptr(session))
		}
	}
	classes := []struct {
		id   uint32
		name string
	}{{0, "Объект данных"}, {1, "Сертификат"}, {2, "Открытый ключ"}, {3, "Закрытый ключ"}, {4, "Секретный ключ"}}
	for _, cl := range classes {
		value := cl.id
		attr := makeCKAttribute(ckaClass, uintptr(unsafe.Pointer(&value)), 4)
		rv = p.call(fnFindObjectsInit, uintptr(session), uintptr(unsafe.Pointer(&attr[0])), 1)
		runtime.KeepAlive(value)
		if rv != ckrOK {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: ошибка поиска 0x%08X", cl.name, rv))
			continue
		}
		seen := 0
		for seen < 2000 {
			var objects [32]uint32
			var count uint32
			rv = p.call(fnFindObjects, uintptr(session), uintptr(unsafe.Pointer(&objects[0])), uintptr(len(objects)), uintptr(unsafe.Pointer(&count)))
			if rv != ckrOK {
				report.Errors = append(report.Errors, fmt.Sprintf("%s: ошибка чтения 0x%08X", cl.name, rv))
				break
			}
			if count == 0 {
				break
			}
			if count > uint32(len(objects)) {
				break
			}
			for _, obj := range objects[:count] {
				rec := objectInfo{Class: cl.name, Attributes: map[string]any{}}
				if b, ok := p.attr(session, obj, ckaLabel, 4096); ok {
					rec.Label = trimField(b)
				}
				if rec.Label == "" {
					rec.Label = "(без метки)"
				}
				if b, ok := p.attr(session, obj, ckaID, 4096); ok {
					rec.ID = strings.ToUpper(hex.EncodeToString(b))
				}
				for _, a := range []struct {
					label string
					id    uint32
				}{{"CKA_PRIVATE", ckaPrivate}, {"CKA_TOKEN", ckaToken}, {"CKA_SENSITIVE", ckaSensitive}, {"CKA_EXTRACTABLE", ckaExtractable}, {"CKA_NEVER_EXTRACTABLE", ckaNeverExtractable}, {"CKA_ALWAYS_SENSITIVE", ckaAlwaysSensitive}, {"CKA_SIGN", ckaSign}, {"CKA_VERIFY", ckaVerify}, {"CKA_MODIFIABLE", ckaModifiable}} {
					b, ok := p.attr(session, obj, a.id, 16)
					rec.Attributes[a.label] = attrBool(b, ok)
				}
				// Extra non-secret metadata for reproducible diagnostics. Never query
				// CKA_VALUE for private/secret keys or any secret key components.
				for _, a := range []struct {
					name string
					id   uint32
				}{{"CKA_ENCRYPT", ckaEncrypt}, {"CKA_DECRYPT", ckaDecrypt}, {"CKA_WRAP", ckaWrap}, {"CKA_UNWRAP", ckaUnwrap}, {"CKA_DERIVE", ckaDerive}} {
					b, ok := p.attr(session, obj, a.id, 16)
					rec.Attributes[a.name] = attrBool(b, ok)
				}
				if cl.id == 0 || cl.id == 1 || cl.id == 2 {
					for _, a := range []struct {
						name string
						id   uint32
					}{{"CKA_APPLICATION", ckaApplication}, {"CKA_OBJECT_ID", ckaObjectID}, {"CKA_ISSUER", ckaIssuer}, {"CKA_SERIAL_NUMBER", ckaSerialNumber}, {"CKA_SUBJECT", ckaSubject}, {"CKA_EC_PARAMS", ckaECParams}, {"CKA_EC_POINT", ckaECPoint}} {
						if b, ok := p.attr(session, obj, a.id, 64*1024); ok {
							rec.Attributes[a.name+"_HEX"] = strings.ToUpper(hex.EncodeToString(b))
						}
					}
				}
				if cl.id == 1 {
					if b, ok := p.attr(session, obj, ckaCertificateType, 16); ok && len(b) >= 4 {
						rec.Attributes["CKA_CERTIFICATE_TYPE"] = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
					}
				}
				if b, ok := p.attr(session, obj, ckaKeyType, 16); ok && len(b) >= 4 {
					rec.Attributes["CKA_KEY_TYPE"] = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
				}
				if cl.id == 1 {
					// Only certificate CKA_VALUE is exported, never private or secret key value.
					if cert, ok := p.attr(session, obj, ckaValue, 8*1024*1024); ok && len(cert) > 1 && cert[0] == 0x30 {
						rec.Cert = cert
						sum := sha256.Sum256(cert)
						rec.CertSHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))
						rec.CertLength = len(cert)
						rec.Export = "Можно сохранить .CER"
					}
				} else if cl.id == 0 || cl.id == 2 {
					// Read CKA_VALUE ONLY for explicitly public data/public-key objects.
					// There is no CKA_VALUE request for private or secret key classes.
					if rec.Attributes["CKA_PRIVATE"] == false {
						if publicValue, ok := p.attr(session, obj, ckaValue, 1024*1024); ok {
							rec.PublicData = publicValue
							sum := sha256.Sum256(publicValue)
							rec.DataSHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))
							rec.DataLength = len(publicValue)
							rec.DataRead = "ok"
						} else {
							rec.DataRead = "unavailable-or-over-limit"
						}
					} else {
						rec.DataRead = "not-read-private"
					}
				} else if cl.id == 3 {
					ext := rec.Attributes["CKA_EXTRACTABLE"]
					if ext == false {
						rec.Export = "Экспорт запрещён (CKA_EXTRACTABLE=false)"
					} else if ext == true {
						rec.Export = "Флаг разрешён; экспорт не выполняется"
					} else {
						rec.Export = "Экспорт неизвестен"
					}
					if rec.Attributes["CKA_NEVER_EXTRACTABLE"] == true {
						rec.Export += "; NEVER_EXTRACTABLE=true"
					}
				}
				report.Objects = append(report.Objects, rec)
			}
			seen += int(count)
		}
		p.call(fnFindObjectsFinal, uintptr(session))
	}
	return report, nil
}
//go:build windows

package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsTabstop          = 0x10000
	wsOverlappedWindow = 0x00CF0000
	wsVscroll          = 0x200000
	wsBorder           = 0x800000
	wsClipChildren     = 0x02000000
	wsClipSiblings     = 0x04000000
	esMultiline        = 0x0004
	esPassword         = 0x0020
	esReadOnly         = 0x0800
	esAutoVscroll      = 0x0040
	lbsNotify          = 0x0001
	cbsDropDownList    = 0x0003
	wmCreate           = 1
	wmDestroy          = 2
	wmSize             = 5
	wmCommand          = 0x111
	wmTimer            = 0x113
	wmSetfont          = 0x30
	wmCtlColorStatic   = 0x138
	wmCtlColorEdit     = 0x133
	lbAddString        = 0x180
	lbReset            = 0x184
	lbGetCurSel        = 0x188
	cbAddString        = 0x143
	cbReset            = 0x14B
	cbGetCurSel        = 0x147
	cbSetCurSel        = 0x14E
	swShow             = 5
	mbIconError        = 0x10
	mbIconInfo         = 0x40
	ofnExplorer        = 0x80000
	ofnFileMustExist   = 0x1000
	ofnOverwritePrompt = 0x2
	idBrowse           = 100
	idFind             = 101
	idScan             = 102
	idSaveCert         = 103
	idSavePEM          = 104
	idSaveJSON         = 105
	idOpenZIP          = 106
	idObjectList       = 107
	idScanPIN          = 108
	idSaveZIP          = 109
	idSaveFolder       = 110
	idImportCSP        = 111
	idImportDir        = 112
	idOpenCSP          = 113
	idDiagnosticCSP    = 114
	idCSPRefresh       = 115
	idCSPCopy          = 116
	idCSPBind          = 117
	idTabDevices       = 118
	idTabImport        = 119
	idTabVerify        = 120
	idTabTools         = 121
	idBackupLocal      = 122
	idDirectMedia      = 123
	idOpenLog          = 124
	idDeviceSelect     = 125
	idCOMAudit         = 126
	idCOMReaders       = 127
	idHardwareCSP      = 128
	idCloneLocalTest   = 129
	wmGetMinMaxInfo    = 0x24
	wmWorkDone         = 0x8000 + 31
)

var (
	user32         = syscall.NewLazyDLL("user32.dll")
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	gdi32          = syscall.NewLazyDLL("gdi32.dll")
	comdlg32       = syscall.NewLazyDLL("comdlg32.dll")
	pCreateWindow  = user32.NewProc("CreateWindowExW")
	pSendMessage   = user32.NewProc("SendMessageW")
	pMessageBox    = user32.NewProc("MessageBoxW")
	pSetWindowText = user32.NewProc("SetWindowTextW")
	pMoveWindow    = user32.NewProc("MoveWindow")
	pDefWindowProc = user32.NewProc("DefWindowProcW")
	pGetWindowText = user32.NewProc("GetWindowTextW")
	pSetFocus      = user32.NewProc("SetFocus")
	pShowWindow    = user32.NewProc("ShowWindow")
	pGetClientRect = user32.NewProc("GetClientRect")
	pUi            *window
)

type wclass struct {
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
}
type msg struct {
	Hwnd    uintptr
	Message uint32
	Wparam  uintptr
	Lparam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
	Private uint32
}
type openFilename struct {
	StructSize      uint32
	Owner           uintptr
	Instance        uintptr
	Filter          *uint16
	CustomFilter    *uint16
	MaxCustomFilter uint32
	FilterIndex     uint32
	File            *uint16
	MaxFile         uint32
	FileTitle       *uint16
	MaxFileTitle    uint32
	InitialDir      *uint16
	Title           *uint16
	Flags           uint32
	FileOffset      uint16
	FileExtension   uint16
	DefExt          *uint16
	CustData        uintptr
	Hook            uintptr
	Template        *uint16
	Reserved        uintptr
	ReservedDWORD   uint32
	FlagsEx         uint32
}

func u16(s string) *uint16 { return syscall.StringToUTF16Ptr(s) }
func sm(h uintptr, m uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessage.Call(h, uintptr(m), w, l)
	return r
}
func setText(h uintptr, s string) {
	pSetWindowText.Call(h, uintptr(unsafe.Pointer(u16(s))))
	// The report is a read-only multiline EDIT. Force its own background to
	// be erased after replacing a report; RedrawWindow(parent) alone is not
	// enough when the child was hidden or the scroll position changed.
	if pUi != nil && h != 0 && h == pUi.details {
		const emSetSel = 0xB1
		sm(h, emSetSel, 0, 0)
		user32.NewProc("RedrawWindow").Call(h, 0, 0, 0x0001|0x0004|0x0100)
	}
}
func show(h uintptr, visible bool) {
	if h == 0 {
		return
	}
	flag := uintptr(0)
	if visible {
		flag = 5
	}
	pShowWindow.Call(h, flag)
}
func move(h uintptr, x, y, w, hei int) {
	pMoveWindow.Call(h, uintptr(x), uintptr(y), uintptr(w), uintptr(hei), 1)
}
func alert(title, text string, typ uintptr) {
	pMessageBox.Call(pUi.hwnd, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), typ)
}
func getText(h uintptr) string {
	buf := make([]uint16, 2048)
	pGetWindowText.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}
func ctrl(class, text string, style uint32, id int, parent uintptr) uintptr {
	r, _, _ := pCreateWindow.Call(0, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))), uintptr(style|wsClipSiblings),
		0, 0, 100, 24, parent, uintptr(id), pUi.instance, 0)
	if r != 0 && pUi.font != 0 {
		sm(r, wmSetfont, pUi.font, 1)
	}
	return r
}
func chooseFile(owner uintptr, save bool, filter, title, defext string) (string, bool) {
	name := make([]uint16, 2048)
	filterUTF16 := append(utf16.Encode([]rune(filter)), 0)
	flt := &filterUTF16[0]
	ofn := openFilename{StructSize: uint32(unsafe.Sizeof(openFilename{})), Owner: owner, Filter: flt, File: &name[0], MaxFile: uint32(len(name)), Title: u16(title), Flags: ofnExplorer}
	if save {
		ofn.Flags |= ofnOverwritePrompt
		if defext != "" {
			ofn.DefExt = u16(defext)
		}
	} else {
		ofn.Flags |= ofnFileMustExist
	}
	var r uintptr
	if save {
		r, _, _ = comdlg32.NewProc("GetSaveFileNameW").Call(uintptr(unsafe.Pointer(&ofn)))
	} else {
		r, _, _ = comdlg32.NewProc("GetOpenFileNameW").Call(uintptr(unsafe.Pointer(&ofn)))
	}
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(name), true
}

type window struct {
	page                                                                                                                                                                                                                                                                                                                                               int
	lastCSPResult                                                                                                                                                                                                                                                                                                                                      string
	brand, navCaption, navDevices, navImport, navVerify, navTools, pageTitle, pageDescription, pageHint, separator, infoLabel2                                                                                                                                                                                                                         uintptr
	titleFont, brandFont, hintFont                                                                                                                                                                                                                                                                                                                     uintptr
	hwnd, instance, font                                                                                                                                                                                                                                                                                                                               uintptr
	header, subtitle, libLabel, libEdit, libBrowse, findBtn, devLabel, devices, scanBtn, infoLabel, list, details, status, saveCert, savePEM, saveJSON, openZIP, saveZIP, saveFolder, importCSP, importDir, openCSP, backupLocal, diagnosticCSP, directMedia, directMediaImport, openLog, comAudit, cspLabel, cspOptions, cspRefresh, cspCopy, cspBind uintptr
	comReaders, hardwareCSP, cloneLocalTest                                                                                                                                                                                                                                                                                                            uintptr
	pinLabel, pinEdit, pinBtn                                                                                                                                                                                                                                                                                                                          uintptr
	devs                                                                                                                                                                                                                                                                                                                                               []deviceInfo
	readers                                                                                                                                                                                                                                                                                                                                            []string
	findWarnings                                                                                                                                                                                                                                                                                                                                       []string
	cspNames                                                                                                                                                                                                                                                                                                                                           []string
	cspStagedCert                                                                                                                                                                                                                                                                                                                                      string
	report                                                                                                                                                                                                                                                                                                                                             *scanReport
	busy                                                                                                                                                                                                                                                                                                                                               bool
	workMu                                                                                                                                                                                                                                                                                                                                             sync.Mutex
	pending                                                                                                                                                                                                                                                                                                                                            *workerResponse
}

// Four focused views replace the original wall of technical buttons.
// All device reads and file-container imports still use the existing workers.
func (a *window) create() {
	a.brand = ctrl("STATIC", "RUTOKEN  INSPECTOR", wsChild|wsVisible, 0, a.hwnd)
	a.navCaption = ctrl("STATIC", "ДИАГНОСТИКА  /  CSP", wsChild|wsVisible, 0, a.hwnd)
	a.navDevices = ctrl("BUTTON", "1   Устройства", wsChild|wsVisible|wsTabstop, idTabDevices, a.hwnd)
	a.navImport = ctrl("BUTTON", "2   Файловые контейнеры", wsChild|wsVisible|wsTabstop, idTabImport, a.hwnd)
	a.navVerify = ctrl("BUTTON", "3   Проверить в CSP", wsChild|wsVisible|wsTabstop, idTabVerify, a.hwnd)
	a.navTools = ctrl("BUTTON", "Диагностика", wsChild|wsVisible|wsTabstop, idTabTools, a.hwnd)
	a.pageTitle = ctrl("STATIC", "Подключённые ключи", wsChild|wsVisible, 0, a.hwnd)
	a.pageDescription = ctrl("STATIC", "Найдите носитель, выберите контейнер и проверьте допустимые способы работы с ним.", wsChild|wsVisible, 0, a.hwnd)
	a.pageHint = ctrl("STATIC", "ШАГ 1 / 3     Носитель и контейнер", wsChild|wsVisible, 0, a.hwnd)
	a.separator = ctrl("STATIC", "────────────────────────────────────────────────────────────────────────────────────────", wsChild|wsVisible, 0, a.hwnd)
	a.header = ctrl("STATIC", "", wsChild|wsVisible, 0, a.hwnd)
	a.subtitle = ctrl("STATIC", "Работа с ключами КриптоПро.\r\nСуществующие контейнеры\r\nне изменяются.", wsChild|wsVisible, 0, a.hwnd)
	a.libLabel = ctrl("STATIC", "Библиотека PKCS#11", wsChild|wsVisible, 0, a.hwnd)
	lib := os.Getenv("SystemRoot") + `\System32\rtPKCS11ECP.dll`
	a.libEdit = ctrl("EDIT", lib, wsChild|wsVisible|wsTabstop|wsBorder, 0, a.hwnd)
	a.libBrowse = ctrl("BUTTON", "Выбрать DLL", wsChild|wsVisible|wsTabstop, idBrowse, a.hwnd)
	a.findBtn = ctrl("BUTTON", "Найти устройства", wsChild|wsVisible|wsTabstop, idFind, a.hwnd)
	a.devLabel = ctrl("STATIC", "Подключённый носитель", wsChild|wsVisible, 0, a.hwnd)
	a.devices = ctrl("COMBOBOX", "", wsChild|wsVisible|wsTabstop|cbsDropDownList|wsVscroll, idDeviceSelect, a.hwnd)
	a.scanBtn = ctrl("BUTTON", "Проверить носитель", wsChild|wsVisible|wsTabstop, idScan, a.hwnd)
	a.pinLabel = ctrl("STATIC", "PIN пользователя", wsChild|wsVisible, 0, a.hwnd)
	a.pinEdit = ctrl("EDIT", "", wsChild|wsVisible|wsTabstop|wsBorder|esPassword, 0, a.hwnd)
	a.pinBtn = ctrl("BUTTON", "Проверить с PIN", wsChild|wsVisible|wsTabstop, idScanPIN, a.hwnd)
	a.cspLabel = ctrl("STATIC", "Контейнер, обнаруженный КриптоПро", wsChild|wsVisible, 0, a.hwnd)
	a.cspOptions = ctrl("COMBOBOX", "", wsChild|wsVisible|wsTabstop|cbsDropDownList|wsVscroll, 0, a.hwnd)
	a.cspRefresh = ctrl("BUTTON", "Обновить список", wsChild|wsVisible|wsTabstop, idCSPRefresh, a.hwnd)
	a.cspCopy = ctrl("BUTTON", "С Рутокена → Crypto Pro (.000)", wsChild|wsVisible|wsTabstop, idCSPCopy, a.hwnd)
	a.cspBind = ctrl("BUTTON", "Установить .CER", wsChild|wsVisible|wsTabstop, idCSPBind, a.hwnd)
	a.infoLabel = ctrl("STATIC", "ОБЪЕКТЫ ТОКЕНА", wsChild|wsVisible, 0, a.hwnd)
	a.infoLabel2 = ctrl("STATIC", "ДЕТАЛИ И ОТЧЁТ", wsChild|wsVisible, 0, a.hwnd)
	a.list = ctrl("LISTBOX", "", wsChild|wsVisible|wsTabstop|wsVscroll|wsBorder|lbsNotify, idObjectList, a.hwnd)
	a.details = ctrl("EDIT", "Найдите устройство или откройте раздел установки готовой копии.\r\n\r\nИмпорт работает только с настоящими файловыми контейнерами КриптоПро.\r\nСертификат и публичный дамп сами по себе не дают права подписания.", wsChild|wsVisible|wsTabstop|wsVscroll|wsBorder|esMultiline|esReadOnly|esAutoVscroll, 0, a.hwnd)
	a.saveCert = ctrl("BUTTON", "Сертификат CER", wsChild|wsVisible|wsTabstop, idSaveCert, a.hwnd)
	a.savePEM = ctrl("BUTTON", "Сертификат PEM", wsChild|wsVisible|wsTabstop, idSavePEM, a.hwnd)
	a.saveZIP = ctrl("BUTTON", "Дамп ZIP", wsChild|wsVisible|wsTabstop, idSaveZIP, a.hwnd)
	a.saveFolder = ctrl("BUTTON", "Тестовая папка .000", wsChild|wsVisible|wsTabstop, idSaveFolder, a.hwnd)
	a.saveJSON = ctrl("BUTTON", "Отчёт JSON", wsChild|wsVisible|wsTabstop, idSaveJSON, a.hwnd)
	a.openZIP = ctrl("BUTTON", "Проверить архив ZIP", wsChild|wsVisible|wsTabstop, idOpenZIP, a.hwnd)
	a.importCSP = ctrl("BUTTON", "Установить из ZIP", wsChild|wsVisible|wsTabstop, idImportCSP, a.hwnd)
	a.importDir = ctrl("BUTTON", "Установить из папки", wsChild|wsVisible|wsTabstop, idImportDir, a.hwnd)
	a.openCSP = ctrl("BUTTON", "Открыть папку Crypto Pro", wsChild|wsVisible|wsTabstop, idOpenCSP, a.hwnd)
	a.backupLocal = ctrl("BUTTON", "Сохранить рабочий HDIMAGE → ZIP", wsChild|wsVisible|wsTabstop, idBackupLocal, a.hwnd)
	a.cloneLocalTest = ctrl("BUTTON", "Копировать локальный HDIMAGE → новую .000", wsChild|wsVisible|wsTabstop, idCloneLocalTest, a.hwnd)
	a.directMedia = ctrl("BUTTON", "Импорт с обычного USB-диска (.key)", wsChild|wsVisible|wsTabstop, idDirectMedia, a.hwnd)
	a.directMediaImport = ctrl("BUTTON", "Импорт с USB-диска с файлами .key", wsChild|wsVisible|wsTabstop, idDirectMedia, a.hwnd)
	a.diagnosticCSP = ctrl("BUTTON", "Проверка дампа 3.0", wsChild|wsVisible|wsTabstop, idDiagnosticCSP, a.hwnd)
	a.openLog = ctrl("BUTTON", "Открыть журнал", wsChild|wsVisible|wsTabstop, idOpenLog, a.hwnd)
	a.comAudit = ctrl("BUTTON", "Проверить запуск COM", wsChild|wsVisible|wsTabstop, idCOMAudit, a.hwnd)
	a.comReaders = ctrl("BUTTON", "Найти Рутокен (COM Lite)", wsChild|wsVisible|wsTabstop, idCOMReaders, a.hwnd)
	a.hardwareCSP = ctrl("BUTTON", "Сверить Рутокен и контейнеры КриптоПро", wsChild|wsVisible|wsTabstop, idHardwareCSP, a.hwnd)
	a.status = ctrl("STATIC", "Готово. Никаких изменений токена без вашего действия. PIN не записывается в отчёт.", wsChild|wsVisible, 0, a.hwnd)
	for _, h := range []uintptr{a.brand, a.navCaption} {
		sm(h, wmSetfont, a.brandFont, 1)
	}
	sm(a.pageTitle, wmSetfont, a.titleFont, 1)
	sm(a.pageHint, wmSetfont, a.hintFont, 1)
	a.renderPage()
}

func (a *window) mainControls() []uintptr {
	return []uintptr{a.libLabel, a.libEdit, a.libBrowse, a.findBtn, a.devLabel, a.devices, a.scanBtn,
		a.pinLabel, a.pinEdit, a.pinBtn, a.cspLabel, a.cspOptions, a.cspRefresh, a.cspCopy, a.cspBind,
		a.infoLabel, a.infoLabel2, a.list, a.details, a.saveCert, a.savePEM, a.saveJSON, a.openZIP, a.saveZIP,
		a.saveFolder, a.importCSP, a.importDir, a.openCSP, a.backupLocal, a.directMedia, a.directMediaImport, a.diagnosticCSP, a.openLog, a.comAudit, a.comReaders, a.hardwareCSP, a.cloneLocalTest}
}
func (a *window) renderPage() {
	for _, h := range a.mainControls() {
		show(h, false)
	}
	visible := func(handles ...uintptr) {
		for _, h := range handles {
			show(h, true)
		}
	}
	switch a.page {
	case 0:
		setText(a.pageTitle, "Подключённые ключи")
		setText(a.pageDescription, "Диагностика подключённых носителей и просмотр доступных контейнеров КриптоПро CSP.")
		setText(a.pageHint, "ШАГ 1 / 3     Определение носителя и ключа")
		visible(a.devLabel, a.devices, a.findBtn, a.scanBtn, a.cspLabel, a.cspOptions, a.cspRefresh, a.cspCopy, a.hardwareCSP, a.details)
	case 1:
		setText(a.pageTitle, "Работа с готовыми контейнерами")
		setText(a.pageDescription, "Импорт файловых контейнеров и резервная копия локального HDIMAGE. Для Рутокена используйте раздел «Устройства».")
		setText(a.pageHint, "ШАГ 2 / 3     Импорт ZIP или каталога .000")
		visible(a.importCSP, a.importDir, a.openCSP, a.backupLocal, a.cloneLocalTest, a.cspLabel, a.cspOptions, a.cspRefresh, a.cspBind, a.details)
	case 2:
		setText(a.pageTitle, "Проверка КриптоПро")
		setText(a.pageDescription, "Убедитесь, что контейнер найден в HDIMAGE. Работу подписи подтвердите в КриптоПро без токена.")
		setText(a.pageHint, "ШАГ 3 / 3     Обнаружение, сертификат, подпись")
		visible(a.cspLabel, a.cspOptions, a.cspRefresh, a.cspBind, a.openCSP, a.openZIP, a.details)
	case 3:
		setText(a.pageTitle, "Диагностика устройства")
		setText(a.pageDescription, "Для специалистов: проверка COM Lite, КриптоПро, сертификатов и диагностика без чтения закрытых ключей.")
		setText(a.pageHint, "РАСШИРЕННЫЙ РЕЖИМ     Без извлечения закрытых ключей")
		visible(a.libLabel, a.libEdit, a.libBrowse, a.devLabel, a.devices, a.findBtn, a.scanBtn,
			a.pinLabel, a.pinEdit, a.pinBtn, a.infoLabel, a.infoLabel2, a.list, a.details, a.saveCert, a.savePEM,
			a.saveJSON, a.saveZIP, a.openLog, a.comReaders, a.comAudit)
	}
	for i, h := range []uintptr{a.navDevices, a.navImport, a.navVerify, a.navTools} {
		labels := []string{"1   Устройства", "2   Файловые контейнеры", "3   Проверить в CSP", "Диагностика"}
		if i == a.page {
			labels[i] = "●  " + strings.TrimLeft(labels[i], " 123")
		}
		setText(h, labels[i])
	}
	a.updateSelectedDevice()
}
func (a *window) switchPage(page int) {
	if page < 0 || page > 3 {
		return
	}
	a.page = page
	a.renderPage()
	var rect struct{ Left, Top, Right, Bottom int32 }
	pGetClientRect.Call(a.hwnd, uintptr(unsafe.Pointer(&rect)))
	a.layout(int(rect.Right), int(rect.Bottom))
	if page == 3 {
		setText(a.details, "Диагностика выбранного устройства. Для Рутокен S сканирование PKCS#11 отключено; используйте проверку через КриптоПро.\r\n\r\nПолный журнал можно открыть кнопкой ниже.")
	}
	// When a large multiline EDIT is hidden and shown again, Windows may leave
	// stale glyphs in the parent if the old regions are not invalidated.
	user32.NewProc("RedrawWindow").Call(a.hwnd, 0, 0, 0x0001|0x0004|0x0080)
}
func (a *window) layout(width, height int) {
	// All positions are recomputed from the ACTUAL client size; nothing is
	// extended beyond the right edge. Diagnostic actions use two compact rows.
	// Windows enforces a minimum track size through WM_GETMINMAXINFO below.
	if width < 920 {
		width = 920
	}
	if height < 625 {
		height = 625
	}
	navWidth := 210
	if width < 1070 {
		navWidth = 188
	}
	left := navWidth + 24
	contentWidth := width - left - 24
	right := left + contentWidth
	move(a.brand, 20, 24, navWidth-25, 38)
	move(a.navCaption, 20, 77, navWidth-25, 28)
	for i, h := range []uintptr{a.navDevices, a.navImport, a.navVerify, a.navTools} {
		y := 125 + i*55
		if i == 3 {
			y = 334
		}
		move(h, 16, y, navWidth-25, 42)
	}
	move(a.header, 20, height-104, navWidth-28, 18)
	move(a.subtitle, 20, height-81, navWidth-28, 59)
	move(a.pageHint, left, 21, contentWidth, 23)
	move(a.pageTitle, left, 51, contentWidth, 42)
	move(a.pageDescription, left, 101, contentWidth, 30)
	move(a.separator, left, 140, contentWidth, 8)
	bottom := height - 68
	if a.page == 0 {
		move(a.devLabel, left, 163, contentWidth, 23)
		move(a.devices, left, 192, contentWidth-316, 250)
		move(a.findBtn, right-308, 191, 142, 32)
		move(a.scanBtn, right-157, 191, 157, 32)
		move(a.cspLabel, left, 245, contentWidth, 23)
		move(a.cspOptions, left, 274, contentWidth-173, 260)
		move(a.cspRefresh, right-164, 274, 164, 33)
		move(a.cspCopy, left, 327, (contentWidth-12)/2, 39)
		move(a.hardwareCSP, left+(contentWidth-12)/2+12, 327, (contentWidth-12)/2, 39)
		move(a.details, left, 426, contentWidth, bottom-426)
	} else if a.page == 1 {
		buttonW := (contentWidth - 14) / 2
		move(a.importCSP, left, 163, buttonW, 43)
		move(a.importDir, left+buttonW+14, 163, buttonW, 43)
		move(a.backupLocal, left, 217, buttonW, 40)
		move(a.openCSP, left+buttonW+14, 217, buttonW, 40)
		move(a.cloneLocalTest, left, 268, contentWidth, 42)
		move(a.cspLabel, left, 324, contentWidth, 23)
		move(a.cspOptions, left, 353, contentWidth-320, 260)
		move(a.cspRefresh, right-312, 353, 150, 34)
		move(a.cspBind, right-153, 353, 153, 34)
		move(a.details, left, 403, contentWidth, bottom-403)
	} else if a.page == 2 {
		move(a.cspLabel, left, 162, contentWidth, 23)
		move(a.cspOptions, left, 191, contentWidth-166, 260)
		move(a.cspRefresh, right-158, 191, 158, 34)
		buttonW := (contentWidth - 20) / 3
		move(a.cspBind, left, 249, buttonW, 42)
		move(a.openZIP, left+buttonW+10, 249, buttonW, 42)
		move(a.openCSP, left+2*buttonW+20, 249, buttonW, 42)
		move(a.details, left, 315, contentWidth, bottom-315)
	} else {
		// The old interface placed six buttons in one 900px row. At common
		// Windows scaling factors they went off-screen and covered each other.
		move(a.libLabel, left, 160, 154, 23)
		move(a.libEdit, left+157, 155, contentWidth-284, 31)
		move(a.libBrowse, right-119, 155, 119, 31)
		move(a.devLabel, left, 205, 154, 23)
		move(a.devices, left+157, 200, contentWidth-477, 250)
		move(a.findBtn, right-311, 200, 147, 33)
		move(a.scanBtn, right-156, 200, 156, 33)
		move(a.pinLabel, left, 250, 290, 23)
		move(a.pinEdit, left+295, 246, 153, 31)
		move(a.pinBtn, left+460, 246, 190, 34)
		cols := (contentWidth - 14) * 37 / 100
		move(a.infoLabel, left, 293, cols, 23)
		move(a.infoLabel2, left+cols+14, 293, contentWidth-cols-14, 23)
		panelBottom := height - 162
		move(a.list, left, 321, cols, panelBottom-321)
		move(a.details, left+cols+14, 321, contentWidth-cols-14, panelBottom-321)
		firstY := height - 151
		secondY := height - 110
		w1 := (contentWidth - 30) / 4
		move(a.saveCert, left, firstY, w1, 34)
		move(a.savePEM, left+w1+10, firstY, w1, 34)
		move(a.saveJSON, left+2*(w1+10), firstY, w1, 34)
		move(a.saveZIP, left+3*(w1+10), firstY, w1, 34)
		w2 := (contentWidth - 20) / 3
		move(a.openLog, left, secondY, w2, 34)
		move(a.comReaders, left+w2+10, secondY, w2, 34)
		move(a.comAudit, left+2*(w2+10), secondY, w2, 34)
	}
	move(a.status, left, height-48, contentWidth, 28)
}

// Keep the supported vendor copy action available for all token models.
// CryptoPro decides whether each selected key is exportable.  A refused
// operation is never reported as a created .000 folder.
func (a *window) updateSelectedDevice() {
	if a.page != 0 {
		return
	}
	idx := int(sm(a.devices, cbGetCurSel, 0, 0))
	show(a.hardwareCSP, true)
	if idx < 0 || idx >= len(a.devs) {
		show(a.cspCopy, false)
		return
	}
	show(a.cspCopy, true)
	if isLegacyRutokenS(a.devs[idx]) {
		setText(a.pageDescription, "Рутокен S: штатный перенос CSP в новую папку .000, если экспорт разрешён. Отказ 0x8009000B не обходится.")
	} else {
		setText(a.pageDescription, "Рутокен: копирование через КриптоПро в .000 при разрешении ключа. Аппаратный неизвлекаемый ключ не копируется.")
	}
}

func (a *window) explainMissingScan() {
	idx := int(sm(a.devices, cbGetCurSel, 0, 0))
	if idx >= 0 && idx < len(a.devs) && isLegacyRutokenS(a.devs[idx]) {
		alert("Рутокен S: доступ через КриптоПро", "Для этой смарт-карты сканирование объектов через старую PKCS#11 DLL отключено из-за сбоя драйвера.\r\n\r\nСписок контейнеров смотрите через «Найти CSP». Публичный диагностический ZIP без сканирования не создаётся; он не был бы рабочей копией ключа.", mbIconInfo)
		return
	}
	alert("Нет отчёта", "Сначала выполните сканирование устройства. Данные закрытого ключа не экспортируются.", mbIconInfo)
}

func (a *window) openDiagnosticLog() {
	path := logPath()
	if _, err := os.Stat(path); err != nil {
		alert("Журнал не найден", "Журнал диагностики пока не создан: "+path, mbIconInfo)
		return
	}
	if err := exec.Command("notepad.exe", path).Start(); err != nil {
		alert("Не удалось открыть журнал", err.Error(), mbIconError)
	}
}

func (a *window) devicesFound() {
	lib := strings.Trim(getText(a.libEdit), `" `)
	a.startWorker("find", nil, lib)
}
func (a *window) scan() {
	idx := int(sm(a.devices, cbGetCurSel, 0, 0))
	if idx < 0 || idx >= len(a.devs) {
		alert("Нет устройства", "Сначала найдите и выберите Рутокен.", mbIconInfo)
		return
	}
	// Rutoken S uses passive CSP-mode containers. A vendor rtPKCS11.dll
	// repeatedly crashes the 32-bit helper during object enumeration. Instead,
	// use CryptoPro's verified container enumeration without loading that DLL.
	if isLegacyRutokenS(a.devs[idx]) {
		a.startWorker("scan-s-csp", nil, a.devs[idx].Model, a.devs[idx].Serial)
		return
	}
	lib := a.devs[idx].Library
	if lib == "" {
		lib = strings.Trim(getText(a.libEdit), `" `)
	}
	a.startWorker("scan", nil, lib, fmt.Sprint(a.devs[idx].Slot))
}
func (a *window) scanWithPIN() {
	idx := int(sm(a.devices, cbGetCurSel, 0, 0))
	if idx < 0 || idx >= len(a.devs) {
		alert("Нет устройства", "Сначала найдите и выберите Рутокен.", mbIconInfo)
		return
	}
	if a.busy {
		setText(a.status, "Сначала завершите текущую операцию.")
		return
	}
	if isLegacyRutokenS(a.devs[idx]) {
		// S/CSP mode does not need the user's PIN for *enumeration*.
		// Erase text before starting. Never pass it to CryptoPro commands.
		setText(a.pinEdit, "")
		a.startWorker("scan-s-csp", nil, a.devs[idx].Model, a.devs[idx].Serial)
		return
	}
	pin := []byte(getText(a.pinEdit))
	setText(a.pinEdit, "") // Clear the masked control immediately.
	if len(pin) == 0 || len(pin) > 128 {
		clear(pin)
		alert("PIN", "Введите PIN пользователя (1–128 байт). Не вводите PIN администратора.", mbIconInfo)
		return
	}
	lib := a.devs[idx].Library
	if lib == "" {
		lib = strings.Trim(getText(a.libEdit), `" `)
	}
	a.startWorker("scan-pin", pin, lib, fmt.Sprint(a.devs[idx].Slot))
}
func (a *window) selected() {
	if a.report == nil {
		return
	}
	idx := int(sm(a.list, lbGetCurSel, 0, 0))
	if idx < 0 || idx >= len(a.report.Objects) {
		return
	}
	o := a.report.Objects[idx]
	b, _ := json.MarshalIndent(o, "", "  ")
	setText(a.details, strings.ReplaceAll(string(b), "\n", "\r\n"))
}
func (a *window) exportCert(pem bool) {
	if a.report == nil {
		a.explainMissingScan()
		return
	}
	idx := int(sm(a.list, lbGetCurSel, 0, 0))
	if idx < 0 || idx >= len(a.report.Objects) {
		alert("Не выбран объект", "Выберите сертификат в списке.", mbIconInfo)
		return
	}
	obj := a.report.Objects[idx]
	if obj.Class != "Сертификат" || len(obj.Cert) == 0 {
		alert("Недоступно", "Выбранный объект не содержит доступного X.509 сертификата.", mbIconInfo)
		return
	}
	ext := "cer"
	kind := "Сертификаты DER (*.cer)\x00*.cer\x00Все файлы (*.*)\x00*.*\x00\x00"
	if pem {
		ext = "pem"
		kind = "Сертификаты PEM (*.pem)\x00*.pem\x00Все файлы (*.*)\x00*.*\x00\x00"
	}
	path, ok := chooseFile(a.hwnd, true, kind, "Сохранить сертификат", ext)
	if !ok {
		return
	}
	data := obj.Cert
	if pem {
		b64 := base64.StdEncoding.EncodeToString(data)
		var lines []string
		for len(b64) > 64 {
			lines = append(lines, b64[:64])
			b64 = b64[64:]
		}
		if b64 != "" {
			lines = append(lines, b64)
		}
		data = []byte("-----BEGIN CERTIFICATE-----\r\n" + strings.Join(lines, "\r\n") + "\r\n-----END CERTIFICATE-----\r\n")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		alert("Ошибка записи", err.Error(), mbIconError)
		return
	}
	setText(a.status, "Сохранён сертификат: "+filepath.Base(path))
}
func (a *window) saveReport() {
	if a.report == nil {
		a.explainMissingScan()
		return
	}
	path, ok := chooseFile(a.hwnd, true, "Отчёт JSON (*.json)\x00*.json\x00Все файлы (*.*)\x00*.*\x00\x00", "Сохранить диагностический отчёт", "json")
	if !ok {
		return
	}
	b, err := json.MarshalIndent(a.report, "", "  ")
	if err == nil {
		err = os.WriteFile(path, b, 0600)
	}
	if err != nil {
		alert("Ошибка записи", err.Error(), mbIconError)
		return
	}
	setText(a.status, "Отчёт сохранён: "+filepath.Base(path))
}

// saveDumpZIP writes ONLY public objects already gathered by the read-only scan.
// This is a logical PKCS#11 export; it is NOT a raw card filesystem image or
// a backup of an operational signing key.
func (a *window) saveDumpZIP() {
	if a.report == nil {
		a.explainMissingScan()
		return
	}
	path, ok := chooseFile(a.hwnd, true, "ZIP архивы (*.zip)\x00*.zip\x00Все файлы (*.*)\x00*.*\x00\x00", "Сохранить логический дамп PKCS#11", "zip")
	if !ok {
		return
	}
	if err := writeEnhancedDumpZIP(path, a.report); err != nil {
		alert("Ошибка ZIP", err.Error(), mbIconError)
		return
	}
	setText(a.status, "Расширенный дамп сохранён: "+filepath.Base(path)+". Закрытых ключей в архиве нет.")
}

// validate hashes and observed lengths BEFORE committing a safe public-data archive.
func writePublicDumpZIP(path string, report *scanReport) error {
	if report == nil {
		return fmt.Errorf("пустой отчёт")
	}
	tempPath := path + ".tmp"
	f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w := zip.NewWriter(f)
	fail := func(e error) error { _ = w.Close(); _ = f.Close(); _ = os.Remove(tempPath); return e }
	put := func(name string, payload []byte) error {
		f, err := w.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(payload)
		return err
	}
	metadata, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err = put("manifest.json", metadata); err != nil {
		return fail(err)
	}
	readme := "Rutoken Inspector 3 v0.9 - LOGICAL PKCS#11 READ-ONLY EXPORT\n\n" +
		"This archive contains only readable public data and certificates plus metadata.\n" +
		"Not a full token memory image. No private-key CKA_VALUE is requested or included.\n" +
		"No claim of compatibility with CryptoPro key container or third-party private-key copies.\n" +
		"CKA_EXTRACTABLE=false and CKA_NEVER_EXTRACTABLE=true prohibit private-key export.\n"
	if err = put("README.txt", []byte(readme)); err != nil {
		return fail(err)
	}
	for i, obj := range report.Objects {
		if obj.Class == "Сертификат" && len(obj.Cert) > 0 {
			if len(obj.Cert) != obj.CertLength {
				return fail(fmt.Errorf("несовпадение размера сертификата %d", i))
			}
			hash := sha256.Sum256(obj.Cert)
			if strings.ToUpper(hex.EncodeToString(hash[:])) != obj.CertSHA256 {
				return fail(fmt.Errorf("несовпадение SHA256 сертификата %d", i))
			}
			if err = put(fmt.Sprintf("public/%03d_certificate.cer", i), obj.Cert); err != nil {
				return fail(err)
			}
		}
		if (obj.Class == "Объект данных" || obj.Class == "Открытый ключ") && obj.Attributes["CKA_PRIVATE"] == false && obj.DataRead == "ok" {
			if len(obj.PublicData) != obj.DataLength {
				return fail(fmt.Errorf("несовпадение размера публичного объекта %d", i))
			}
			hash := sha256.Sum256(obj.PublicData)
			if strings.ToUpper(hex.EncodeToString(hash[:])) != obj.DataSHA256 {
				return fail(fmt.Errorf("несовпадение SHA256 публичного объекта %d", i))
			}
			if len(obj.PublicData) > 1024*1024 {
				return fail(fmt.Errorf("объект %d превышает лимит", i))
			}
			kind := "data"
			if obj.Class == "Открытый ключ" {
				kind = "public_key"
			}
			if err = put(fmt.Sprintf("public/%03d_%s.bin", i, kind), obj.PublicData); err != nil {
				return fail(err)
			}
		}
	}
	if err = w.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	// Win32 MoveFileEx can atomically replace an existing ZIP selected by the
	// Save As dialog, unlike os.Rename on some Windows configurations.
	src, err := syscall.UTF16PtrFromString(tempPath)
	if err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	dst, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	const movefileReplaceExisting = 0x1
	const movefileWriteThrough = 0x8
	ret, _, winErr := kernel32.NewProc("MoveFileExW").Call(
		uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), movefileReplaceExisting|movefileWriteThrough)
	if ret == 0 {
		_ = os.Remove(tempPath)
		return fmt.Errorf("не удалось сохранить ZIP: %v", winErr)
	}
	return nil
}

func (a *window) saveDumpFolder() {
	if a.report == nil {
		a.explainMissingScan()
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		alert("Папка пользователя", err.Error(), mbIconError)
		return
	}
	root := filepath.Join(home, "Downloads")
	if st, er := os.Stat(root); er != nil || !st.IsDir() {
		root = home
	}
	path, err := exportPublicCSPTestFolder(root, a.report)
	if err != nil {
		alert("Ошибка экспорта папки", err.Error(), mbIconError)
		return
	}
	msg := "Создана папка:\r\n" + path + "\r\n\r\nЭто проверочная папка, а не ключевой контейнер.\r\n" +
		"Файлы закрытого ключа отсутствуют; КриптоПро, скорее всего, её не распознает.\r\n" +
		"Копируйте вручную, не перезаписывая существующие контейнеры."
	setText(a.status, "Папка *.000 создана в Downloads; закрытый ключ отсутствует")
	alert("Папка для ручной проверки", msg, mbIconInfo)
}

func cspDestination() (string, error) {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return "", fmt.Errorf("не найдена переменная LOCALAPPDATA")
	}
	return filepath.Join(local, "Crypto Pro"), nil
}

func (a *window) performQuickImport(plan *quickPlan) {
	dest, err := cspDestination()
	if err != nil {
		alert("Неизвестный профиль Windows", err.Error(), mbIconError)
		return
	}
	if err = planQuickNames(plan, dest); err != nil {
		alert("Проверка импорта", err.Error(), mbIconError)
		return
	}
	const mbYesNo = 0x4
	const mbWarning = 0x30
	const idYes = 6
	preview := quickPreview(plan)
	r, _, _ := pMessageBox.Call(a.hwnd, uintptr(unsafe.Pointer(u16(preview))), uintptr(unsafe.Pointer(u16("Подтвердите восстановление файлового CSP-контейнера"))), mbYesNo|mbWarning)
	if r != idYes {
		return
	}
	res, err := installQuick(plan)
	if err != nil {
		alert("Ошибка копирования", err.Error(), mbIconError)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Каталог: %s\r\n\r\n", res.Destination)
	for _, msg := range res.Messages {
		fmt.Fprintf(&b, "Установлен: %s\r\n", msg)
	}
	for _, cert := range res.Certificates {
		fmt.Fprintf(&b, "Сертификат: %s\r\n", cert)
	}
	b.WriteString("\r\nОтключите физический токен. Откройте КриптоПро CSP → Сервис → Протестировать → Обзор (HDIMAGE).\r\n")
	b.WriteString("Если личного сертификата нет в хранилище, установите его штатным мастером КриптоПро с выбором соответствующего контейнера.\r\n")
	b.WriteString("Приложение не меняло реестр и не проверяло соответствие сертификата закрытому ключу.")
	setText(a.status, fmt.Sprintf("Импорт CSP: установлено %d файловых контейнеров", len(res.Created)))
	alert("Контейнеры скопированы", b.String(), mbIconInfo)
	// Immediately proceed to verification without requiring the user to find
	// the next screen manually. The CSP enumeration runs in a worker.
	a.switchPage(2)
	a.refreshCSPContainers()
}

func (a *window) importCSPBackup() {
	source, ok := chooseFile(a.hwnd, false, "ZIP архивы (*.zip)\x00*.zip\x00\x00", "Выберите ZIP с контейнерами КриптоПро", "")
	if !ok {
		return
	}
	plan, err := quickSourcesZip(source)
	if err != nil {
		alert("Не файловый контейнер", err.Error(), mbIconError)
		return
	}
	a.performQuickImport(plan)
}

func (a *window) importCSPFolder() {
	source, ok := chooseFile(a.hwnd, false, "Файл header.key\x00header.key\x00Все файлы (*.*)\x00*.*\x00\x00", "Выберите header.key внутри папки контейнера", "")
	if !ok {
		return
	}
	if !strings.EqualFold(filepath.Base(source), "header.key") {
		alert("Нужен header.key", "Выберите файл header.key внутри исходной папки .000 с шестью файлами .key", mbIconError)
		return
	}
	plan, err := quickSourcesDir(filepath.Dir(source))
	if err != nil {
		alert("Не файловый контейнер", err.Error(), mbIconError)
		return
	}
	a.performQuickImport(plan)
}

func (a *window) importDiagnostic3() {
	source, ok := chooseFile(a.hwnd, false, "ZIP архивы (*.zip)\x00*.zip\x00\x00", "Тест: выберите публичный ZIP-дамп Рутокен 3.0", "")
	if !ok {
		return
	}
	dest, err := cspDestination()
	if err != nil {
		alert("Путь Crypto Pro", err.Error(), mbIconError)
		return
	}
	candidate, err := diagZIP(source, dest)
	if err != nil {
		alert("Неподдерживаемый дамп", err.Error(), mbIconError)
		return
	}
	text := fmt.Sprintf("Будет создан каталог %s\r\n\r\n%s\r\n\r\n",
		filepath.Join(dest, candidate.Target), candidate.Source)
	text += "Только доступные данные и сертификат. Закрытого ключа НЕТ.\r\nКриптоПро CSP не сможет подписывать по такому дампу.\r\nЭто исключительно ручной тест обнаружения каталога. Продолжить?"
	const yesNo = 4
	const warning = 0x30
	const yes = 6
	ret, _, _ := pMessageBox.Call(a.hwnd, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16("Диагностический дамп: не контейнер закрытого ключа"))), yesNo|warning)
	if ret != yes {
		return
	}
	if err = installDiagnostic(candidate, dest); err != nil {
		alert("Ошибка тестового импорта", err.Error(), mbIconError)
		return
	}
	alert("Тестовая папка создана", fmt.Sprintf("Создано: %s\r\nФайлов: %d\r\nЗакрытого ключа нет: подпись работать не будет.", filepath.Join(dest, candidate.Target), len(candidate.Files)), mbIconInfo)
}

// cloneLocalHDIMAGETest demonstrates an authorized file-container copy.
// The source MUST be an existing .000 folder under the current account's
// %LOCALAPPDATA%\\Crypto Pro, not a Rutoken or arbitrary device path.
func (a *window) cloneLocalHDIMAGETest() {
	selected, ok := chooseFile(a.hwnd, false,
		"Контейнер (header.key)\x00header.key\x00Все файлы (*.*)\x00*.*\x00\x00",
		"Учебный тест: выберите header.key существующего локального HDIMAGE", "")
	if !ok {
		return
	}
	if !strings.EqualFold(filepath.Base(selected), "header.key") {
		alert("Выберите header.key", "Выберите header.key в существующем локальном каталоге NNNN.000.", mbIconError)
		return
	}
	src := filepath.Dir(selected)
	plan, err := planLocalCloneTest(src)
	if err != nil {
		alert("Учебная копия невозможна", err.Error(), mbIconError)
		return
	}
	// This is a local authorized file-to-file backup demonstration; never
	// suggest it copied an unexportable token signing key.
	prompt := "УЧЕБНЫЙ ТЕСТ: дублирование уже доступного локального файлового контейнера.\r\n\r\n" +
		"Источник: " + src + "\r\nНазначение: " + filepath.Join(plan.Destination, plan.Candidates[0].Target) +
		"\r\n\r\nШесть файлов .key будут скопированы без изменения байтов, с проверкой SHA-256.\r\n" +
		"ВНИМАНИЕ: новая папка может содержать действительный закрытый ключ; защищайте её.\r\n" +
		"Это НЕ снятие дампа с Рутокен S и НЕ обход запрета на экспорт.\r\n" +
		"Наличие файлов ещё не гарантирует распознавание КриптоПро или работу подписи.\r\n\r\nПродолжить?"
	ret, _, _ := pMessageBox.Call(a.hwnd, uintptr(unsafe.Pointer(u16(prompt))),
		uintptr(unsafe.Pointer(u16("Подтверждение учебного теста"))), 4|0x30)
	if ret != 6 {
		return
	}
	res, err := installQuick(plan)
	if err != nil {
		alert("Ошибка учебного копирования", err.Error(), mbIconError)
		return
	}
	target := filepath.Join(res.Destination, res.Created[0])
	message := "Локальная файловая копия создана:\r\n" + target +
		"\r\n\r\nИсточник сохранён, действующие папки не перезаписаны.\r\n" +
		"Шесть файлов .key сверены по SHA-256.\r\n" +
		"Извлечение ключа с Рутокена НЕ выполнялось.\r\n\r\n" +
		"Проверьте наличие HDIMAGE и возможность подписи через инструменты КриптоПро."
	setText(a.status, "Учебная локальная копия: "+res.Created[0]+" (не с Рутокена)")
	alert("Учебная копия файлового контейнера", message, mbIconInfo)
	a.switchPage(2)
	a.refreshCSPContainers()
}

func (a *window) backupExistingHDIMAGE() {
	srcFile, ok := chooseFile(a.hwnd, false, "Контейнер (header.key)\x00header.key\x00Все файлы (*.*)\x00*.*\x00\x00", "Выберите header.key в рабочем локальном HDIMAGE", "")
	if !ok {
		return
	}
	if !strings.EqualFold(filepath.Base(srcFile), "header.key") {
		alert("Выберите header.key", "Выберите файл header.key внутри локальной папки .000.", mbIconError)
		return
	}
	sourceFolder := filepath.Dir(srcFile)
	if err := validateLocalCSPSource(sourceFolder); err != nil {
		alert("Только локальный контейнер", err.Error(), mbIconError)
		return
	}
	// Confirm separately: unlike certificate export, this ZIP may contain private key data.
	prompt := "Будет создана резервная копия УЖЕ РАБОТАЮЩЕГО локального контейнера: \r\n" + sourceFolder +
		"\r\n\r\nВНИМАНИЕ: архив может содержать закрытый ключ подписи. Храните в защищённом месте и не отправляйте посторонним.\r\n" +
		"Это НЕ копирование ключа с физического Рутокена. Продолжить?"
	ret, _, _ := pMessageBox.Call(a.hwnd, uintptr(unsafe.Pointer(u16(prompt))), uintptr(unsafe.Pointer(u16("Резервная копия HDIMAGE"))), 4|0x30)
	if ret != 6 {
		return
	}
	file, ok := chooseFile(a.hwnd, true, "ZIP архивы (*.zip)\x00*.zip\x00\x00", "Сохранить резервную копию контейнера", "zip")
	if !ok {
		return
	}
	if err := writeLocalCSPBackup(sourceFolder, file); err != nil {
		alert("Архив не создан", err.Error(), mbIconError)
		return
	}
	setText(a.status, "Готова резервная копия локального контейнера: "+filepath.Base(file))
	alert("Резервная копия сохранена", "Архив из шести оригинальных .key (и сертификата, если был рядом) сохранён.\r\nДля установки на другом ПК используйте «Установить из ZIP».\r\nРабота ключа на новом ПК проверяется только в КриптоПро.", mbIconInfo)
}

func (a *window) openCSPDirectory() {
	dest, err := cspDestination()
	if err != nil {
		alert("Неизвестный профиль Windows", err.Error(), mbIconError)
		return
	}
	if err = os.MkdirAll(dest, 0700); err != nil {
		alert("Папка Crypto Pro", err.Error(), mbIconError)
		return
	}
	if err = exec.Command("explorer.exe", dest).Start(); err != nil {
		alert("Проводник", err.Error(), mbIconError)
	}
}
func (a *window) analyzeZip() {
	path, ok := chooseFile(a.hwnd, false, "ZIP архивы (*.zip)\x00*.zip\x00Все файлы (*.*)\x00*.*\x00\x00", "Открыть архив диагностики", "")
	if !ok {
		return
	}
	a.startWorker("zip", nil, path)
}
func (a *window) command(w uintptr) {
	id := int(w & 0xFFFF)
	notify := (w >> 16) & 0xFFFF
	switch id {
	case idTabDevices:
		a.switchPage(0)
	case idDeviceSelect:
		if notify == 1 {
			a.updateSelectedDevice()
		}
	case idTabImport:
		a.switchPage(1)
	case idTabVerify:
		a.switchPage(2)
	case idTabTools:
		a.switchPage(3)
	case idBrowse:
		if name, ok := chooseFile(a.hwnd, false, "Библиотеки (*.dll)\x00*.dll\x00Все файлы (*.*)\x00*.*\x00\x00", "Выберите rtPKCS11ECP.dll", ""); ok {
			setText(a.libEdit, name)
		}
	case idFind:
		a.devicesFound()
	case idScan:
		a.scan()
	case idScanPIN:
		a.scanWithPIN()
	case idSaveCert:
		a.exportCert(false)
	case idSavePEM:
		a.exportCert(true)
	case idSaveJSON:
		a.saveReport()
	case idSaveZIP:
		a.saveDumpZIP()
	case idSaveFolder:
		a.saveDumpFolder()
	case idOpenZIP:
		a.analyzeZip()
	case idImportCSP:
		a.importCSPBackup()
	case idImportDir:
		a.importCSPFolder()
	case idOpenCSP:
		a.openCSPDirectory()
	case idBackupLocal:
		a.backupExistingHDIMAGE()
	case idCloneLocalTest:
		a.cloneLocalHDIMAGETest()
	case idDirectMedia:
		a.copyFromAccessibleMedia()
	case idDiagnosticCSP:
		a.importDiagnostic3()
	case idOpenLog:
		a.openDiagnosticLog()
	case idCOMAudit:
		a.startWorker("com-audit", nil)
	case idCOMReaders:
		a.startWorker("com-readers", nil)
	case idHardwareCSP:
		a.startWorker("hardware-csp", nil)
	case idCSPRefresh:
		a.refreshCSPContainers()
	case idCSPCopy:
		a.copyCSPContainer()
	case idCSPBind:
		a.bindPersonalCertificate()
	case idObjectList:
		if notify == 1 {
			a.selected()
		}
	}
}
func wndproc(hwnd uintptr, message uint32, w, l uintptr) uintptr {
	switch message {
	case wmCreate:
		pUi.hwnd = hwnd
		pUi.create()
		return 0
	case wmGetMinMaxInfo:
		if l != 0 {
			// MINMAXINFO: points at offsets 0,8,16,24,32;
			// ptMinTrackSize = offset 24, x/y are LONG.
			minTrack := (*[10]int32)(unsafe.Pointer(l))
			minTrack[6], minTrack[7] = 970, 710
		}
		return 0
	case wmSize:
		width := int(l & 0xFFFF)
		height := int((l >> 16) & 0xFFFF)
		pUi.layout(width, height)
		return 0
	case wmCommand:
		// Edit controls with ID 0 emit frequent notifications, especially
		// during scrolling. They are not user actions and flooded debug logs.
		if w&0xffff != 0 {
			appendLog(fmt.Sprintf("GUI: WM_COMMAND id=%d code=%d", w&0xffff, (w>>16)&0xffff))
		}
		pUi.command(w)
		return 0
	case wmWorkDone:
		appendLog("GUI: worker response handled on GUI thread")
		pUi.workDone()
		return 0
	case wmCtlColorStatic, wmCtlColorEdit:
		// Windows sends WM_CTLCOLORSTATIC for read-only EDIT controls.
		// They MUST have an opaque background, otherwise a scrolled or
		// updated multiline report paints text on top of previous glyphs.
		if pUi != nil && l == pUi.details {
			bg, _, _ := user32.NewProc("GetSysColor").Call(5) // COLOR_WINDOW
			gdi32.NewProc("SetBkMode").Call(w, 2)             // OPAQUE
			gdi32.NewProc("SetBkColor").Call(w, bg)
			gdi32.NewProc("SetTextColor").Call(w, 0x00202020)
			brush, _, _ := user32.NewProc("GetSysColorBrush").Call(5)
			return brush
		}
		if message == wmCtlColorEdit {
			r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), w, l)
			return r
		}
		// Static labels are deliberately transparent against the window.
		gdi32.NewProc("SetBkMode").Call(w, 1) // TRANSPARENT
		color := uintptr(0x00302A24)          // COLORREF: dark slate
		if l == pUi.pageTitle || l == pUi.brand {
			color = 0x00804518
		}
		if l == pUi.pageDescription || l == pUi.subtitle || l == pUi.status || l == pUi.navCaption {
			color = 0x008A7A65
		}
		if l == pUi.pageHint {
			color = 0x00BD651F
		}
		gdi32.NewProc("SetTextColor").Call(w, color)
		brush, _, _ := user32.NewProc("GetSysColorBrush").Call(5) // COLOR_WINDOW
		return brush
	case wmTimer:
		atomic.StoreInt64(&lastGUIPulse, time.Now().UnixNano())
		return 0
	case wmDestroy:
		user32.NewProc("KillTimer").Call(hwnd, 1)
		user32.NewProc("PostQuitMessage").Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), w, l)
	return r
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--worker" {
		workerMain(os.Args[2:])
		return
	}
	// Windows binds every window and its message queue to its creation thread.
	// Go goroutines are otherwise free to migrate across OS threads, which can
	// leave the GUI permanently unresponsive after a successful worker reply.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	appendLog("GUI started v3.4.1 - independent diagnostic release")
	inst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	makeFont := func(size, weight int, face string) uintptr {
		f, _, _ := gdi32.NewProc("CreateFontW").Call(
			uintptr(int32(-size)), 0, 0, 0, uintptr(weight), 0, 0, 0,
			1, 0, 0, 5, 0, uintptr(unsafe.Pointer(u16(face))))
		return f
	}
	font := makeFont(17, 400, "Segoe UI")
	brandFont := makeFont(20, 700, "Segoe UI")
	titleFont := makeFont(29, 700, "Segoe UI")
	hintFont := makeFont(14, 600, "Segoe UI")
	pUi = &window{instance: inst, font: font, brandFont: brandFont, titleFont: titleFont, hintFont: hintFont}
	className := u16("RutokenInspector3Modern")
	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512) // IDC_ARROW
	wc := wclass{WndProc: syscall.NewCallback(wndproc), Instance: inst, Cursor: cursor, Background: 6, ClassName: className}
	atom, _, _ := user32.NewProc("RegisterClassW").Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return
	}
	hwnd, _, _ := pCreateWindow.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(u16("Rutoken Inspector 3 v3.4.1 — независимая диагностика"))), wsOverlappedWindow|wsVisible|wsClipChildren,
		70, 50, 1280, 830, 0, 0, inst, 0)
	if hwnd == 0 {
		return
	}
	// WM_TIMER is serviced only by the GUI's Win32 message pump.
	atomic.StoreInt64(&lastGUIPulse, time.Now().UnixNano())
	user32.NewProc("SetTimer").Call(hwnd, 1, 1000, 0)
	go watchGUI()
	user32.NewProc("ShowWindow").Call(hwnd, swShow)
	user32.NewProc("UpdateWindow").Call(hwnd)
	var m msg
	getMessage := user32.NewProc("GetMessageW")
	translate := user32.NewProc("TranslateMessage")
	dispatch := user32.NewProc("DispatchMessageW")
	for {
		r, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		translate.Call(uintptr(unsafe.Pointer(&m)))
		dispatch.Call(uintptr(unsafe.Pointer(&m)))
	}
}
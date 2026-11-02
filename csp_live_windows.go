//go:build windows

package main

// Official CryptoPro CSP workflow. Never attempts to read, modify, or clone
// PKCS#11 CKA_VALUE for private-key objects. Transfer is delegated entirely
// to CryptoPro csptest; linking is done by CryptoPro certmgr.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

var cspErrCode = regexp.MustCompile(`(?i)(?:ErrorCode|Error number)\s*[:=]\s*(0x[0-9a-f]+)`)

func cspTool(name string) (string, error) {
	bases := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramW6432")}
	for _, b := range bases {
		if b == "" {
			continue
		}
		candidate := filepath.Join(b, "Crypto Pro", "CSP", name+".exe")
		if f, err := os.Stat(candidate); err == nil && !f.IsDir() {
			return candidate, nil
		}
	}
	if f, err := exec.LookPath(name + ".exe"); err == nil {
		return f, nil
	}
	return "", fmt.Errorf("не найден %s.exe; проверьте установку КриптоПро CSP 5.x", name)
}

func runCSP(ctx context.Context, exe string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return decodeCSPOutput(b), ctx.Err()
	}
	if len(b) > 65536 {
		b = b[:65536]
	}
	return decodeCSPOutput(b), err
}

func decodeCSPOutput(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) {
		return string(b)
	}
	// CryptoPro console applications may emit CP866 on Russian Windows.
	// Decode using the actual Windows OEM code page before showing or reusing FQCNs.
	cp, _, _ := kernel32.NewProc("GetOEMCP").Call()
	n, _, _ := kernel32.NewProc("MultiByteToWideChar").Call(cp, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 || n > 1<<20 {
		return string(b)
	}
	dest := make([]uint16, n)
	got, _, _ := kernel32.NewProc("MultiByteToWideChar").Call(cp, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&dest[0])), n)
	if got == 0 {
		return string(b)
	}
	return syscall.UTF16ToString(dest)
}

func parseCSPNames(output string) []string {
	names := make([]string, 0)
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(line, `\\.\`) && !seen[strings.ToLower(line)] {
			seen[strings.ToLower(line)] = true
			names = append(names, line)
		}
	}
	return names
}

func enumerateCSPContainers() ([]string, string, string) {
	exe, err := cspTool("csptest")
	if err != nil {
		return nil, "", err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := runCSP(ctx, exe, "-keyset", "-enum_cont", "-fqcn", "-verifyc")
	names := parseCSPNames(output)
	if err != nil {
		return nil, output, fmt.Sprintf("КриптоПро не смог перечислить контейнеры: %v", err)
	}
	if len(names) == 0 {
		return nil, output, "КриптоПро не вернул ни одного FQCN. Проверьте считыватели и версию CSP."
	}
	return names, fmt.Sprintf("Источник: %s; результат: %d контейнер(ов).", exe, len(names)), ""
}

func cspSucceeded(out string, err error) bool {
	if err != nil {
		return false
	}
	codes := cspErrCode.FindAllStringSubmatch(out, -1)
	for _, p := range codes {
		if !strings.EqualFold(p[1], "0x00000000") && !strings.EqualFold(p[1], "0x0") {
			return false
		}
	}
	return len(codes) > 0 && (strings.Contains(strings.ToLower(out), "errorcode: 0x00000000") || strings.Contains(strings.ToLower(out), "errorcode: 0x0"))
}

func reportIsHardwareLocked(report *scanReport) bool {
	if report == nil || !report.Authenticated {
		return false
	}
	for _, o := range report.Objects {
		if o.Class != "Закрытый ключ" {
			continue
		}
		if o.Attributes["CKA_EXTRACTABLE"] == false && o.Attributes["CKA_NEVER_EXTRACTABLE"] == true {
			return true
		}
	}
	return false
}

func stageCurrentCert(report *scanReport, selectedIndex int) (string, error) {
	if report == nil {
		return "", errors.New("сначала выполните сканирование токена с PIN")
	}
	var cert []byte
	found := 0
	for i, o := range report.Objects {
		if o.Class == "Сертификат" && len(o.Cert) > 0 && looksDERCertificate(o.Cert) {
			found++
			if found == 1 || i == selectedIndex {
				cert = o.Cert
			}
		}
	}
	if found > 1 {
		if selectedIndex < 0 || selectedIndex >= len(report.Objects) || report.Objects[selectedIndex].Class != "Сертификат" {
			return "", errors.New("на токене несколько сертификатов; выберите соответствующий сертификат в списке объектов")
		}
		cert = report.Objects[selectedIndex].Cert
	}
	if len(cert) == 0 {
		return "", errors.New("на токене не найден читаемый X.509 сертификат; используйте «Экспорт .CER»")
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", errors.New("LOCALAPPDATA не задан")
	}
	dir := filepath.Join(base, "RutokenInspector3", "certificates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	org := safeCertName(strings.ReplaceAll(certOrganization(cert), `"`, ""))
	if org == "" {
		org = "Сертификат"
	}
	hash := sha256.Sum256(cert)
	name := org + "-" + strings.ToUpper(hex.EncodeToString(hash[:6])) + ".cer"
	full := filepath.Join(dir, name)
	if old, err := os.ReadFile(full); err == nil {
		if sha256.Sum256(old) == hash {
			return full, nil
		}
		return "", errors.New("в каталоге уже лежит файл с тем же именем и другим содержимым")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(cert)
	cerr := f.Close()
	if err != nil {
		os.Remove(full)
		return "", err
	}
	if cerr != nil {
		os.Remove(full)
		return "", cerr
	}
	return full, nil
}

// stageCertificateViaCryptoPro exports PUBLIC X.509 data from the currently
// selected CSP source container using the vendor-supported cryptcp utility.
// No private-key bytes or PIN are read. This is optional: older containers may
// not contain an embedded certificate, or cryptcp may not be installed.
func stageCertificateViaCryptoPro(src string) (string, error) {
	exe, err := cspTool("cryptcp")
	if err != nil {
		return "", err
	}
	app := os.Getenv("LOCALAPPDATA")
	if app == "" {
		return "", errors.New("LOCALAPPDATA не задан")
	}
	base := filepath.Join(app, "RutokenInspector3", "certificates")
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	staged := filepath.Join(base, "from-token-"+hex.EncodeToString(nonce[:])+".cer")
	// cryptcp -cspcert -ku -cont FQCN -df file -der : official CryptoPro operation.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, execErr := runCSP(ctx, exe, "-cspcert", "-ku", "-cont", src, "-df", staged, "-der")
	if execErr != nil {
		os.Remove(staged)
		return "", fmt.Errorf("cryptcp: %v; %s", execErr, truncateCSPOutput(output))
	}
	// Some CryptoPro commands emit an error code while returning exit code 0.
	for _, match := range cspErrCode.FindAllStringSubmatch(output, -1) {
		if !strings.EqualFold(match[1], "0x00000000") && !strings.EqualFold(match[1], "0x0") {
			os.Remove(staged)
			return "", fmt.Errorf("cryptcp: %s", match[1])
		}
	}
	der, err := os.ReadFile(staged)
	if err != nil || !looksDERCertificate(der) {
		os.Remove(staged)
		return "", errors.New("cryptcp не выдал корректный сертификат DER")
	}
	hash := sha256.Sum256(der)
	org := safeCertName(strings.ReplaceAll(certOrganization(der), `"`, ""))
	if org == "" {
		org = "Сертификат"
	}
	dest := filepath.Join(base, org+"-"+strings.ToUpper(hex.EncodeToString(hash[:6]))+".cer")
	if old, err := os.ReadFile(dest); err == nil && sha256.Sum256(old) == hash {
		os.Remove(staged)
		return dest, nil
	}
	if _, err := os.Lstat(dest); err == nil {
		os.Remove(staged)
		return "", errors.New("имя сертификата уже занято другим файлом")
	}
	if err := os.Rename(staged, dest); err != nil {
		os.Remove(staged)
		return "", err
	}
	return dest, nil
}

func truncateCSPOutput(s string) string {
	if len(s) > 250 {
		return s[:250]
	}
	return s
}

func (a *window) refreshCSPContainers() {
	a.startWorker("csp-list", nil)
}
func (a *window) selectedCSP() (string, error) {
	i := int(sm(a.cspOptions, cbGetCurSel, 0, 0))
	if i < 0 || i >= len(a.cspNames) {
		return "", errors.New("сначала нажмите «Найти CSP» и выберите контейнер")
	}
	return a.cspNames[i], nil
}

func cspConfirm(hwnd uintptr, title, text string) bool {
	r, _, _ := pMessageBox.Call(hwnd, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), 4|0x30)
	return r == 6
}

func (a *window) copyCSPContainer() {
	if a.busy {
		alert("Занято", "Завершите текущую операцию.", mbIconInfo)
		return
	}
	src, err := a.selectedCSP()
	if err != nil {
		alert("Выбор контейнера", err.Error(), mbIconInfo)
		return
	}
	ref := splitCSPFQCN(src)
	if !ref.isToken {
		alert("Источник", "Для новой копии выберите контейнер физического носителя, а не HDIMAGE.\r\n\r\nДля восстановления готового контейнера используйте «Установить из ZIP».", mbIconInfo)
		return
	}
	// A local copy with the same friendly name is intentionally NOT used as a
	// source and does not prevent creating a new, uniquely named destination.
	// Never delete, rename or overwrite previously installed HDIMAGE copies.
	var current *scanReport
	i := int(sm(a.devices, cbGetCurSel, 0, 0))
	if a.report != nil && i >= 0 && i < len(a.devs) &&
		!isLegacyRutokenS(a.devs[i]) &&
		strings.EqualFold(strings.TrimSpace(a.report.Token.Serial), strings.TrimSpace(a.devs[i].Serial)) {
		current = a.report
	}
	if reportIsHardwareLocked(current) {
		alert("Аппаратный неизвлекаемый ключ", "Для выбранного токена диагностикой установлен запрет CKA_NEVER_EXTRACTABLE=true.\r\n\r\nШтатное копирование невозможно. Подключайте исходный токен либо оформляйте новый ключ.", mbIconInfo)
		return
	}
	// The Win32 GUI must not block on cryptcp, csptest or a driver's PIN dialog.
	// If no certificate is already in a scan, export PUBLIC data later in the
	// worker goroutine. When it is unavailable, copy can still finish and the
	// user can link a certificate manually via «Связать .CER».
	cert := ""
	if current != nil {
		if available, err := stageCurrentCert(current, int(sm(a.list, lbGetCurSel, 0, 0))); err == nil {
			cert = available
		}
	}
	// A fresh, random destination makes this a clean-PC simulation even if
	// an older HDIMAGE with the same source name already exists on this PC.
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		alert("Ошибка", err.Error(), mbIconError)
		return
	}
	target := `\\.\HDIMAGE\RI_` + strings.ToUpper(hex.EncodeToString(nonce[:]))
	// Use the already displayed CSP inventory; never enumerate on the UI thread.
	names := append([]string(nil), a.cspNames...)
	for _, n := range names {
		if strings.EqualFold(n, target) {
			alert("Конфликт", "Сгенерированное имя уже занято; повторите операцию.", mbIconError)
			return
		}
	}
	existing := matchingHDIMAGE(src, names)
	note := "Создаётся НОВАЯ копия со свободным именем. Старые HDIMAGE-контейнеры и сертификаты не изменяются."
	if existing != "" {
		note += "\r\n\r\nСуществующая копия " + existing + " будет сохранена без изменений."
	}
	certText := "будет предпринята автоматическая выгрузка открытого сертификата; при неудаче можно привязать .CER вручную"
	if cert != "" {
		certText = cert
	}
	prompt := fmt.Sprintf("ИСТОЧНИК НА РУТОКЕНЕ:\r\n%s\r\n\r\nНОВЫЙ КОНТЕЙНЕР:\r\n%s\r\n\r\nСЕРТИФИКАТ:\r\n%s\r\n\r\n%s\r\n\r\nКриптоПро может запретить копирование неэкспортируемого ключа. Никакого обхода защиты не выполняется. Продолжить?", src, target, certText, note)
	if !cspConfirm(a.hwnd, "Новая копия с Рутокена — подтверждение", prompt) {
		return
	}
	a.cspStagedCert = cert
	a.startCSPTransfer(src, target, cert)
}

func (a *window) bindPersonalCertificate() {
	if a.busy {
		return
	}
	dst, err := a.selectedCSP()
	if err != nil {
		alert("Сначала выберите контейнер", err.Error(), mbIconInfo)
		return
	}
	if !strings.HasPrefix(strings.ToUpper(dst), strings.ToUpper(`\\.\HDIMAGE\`)) {
		alert("Требуется HDIMAGE", "Для автономной работы выбирайте файловый контейнер HDIMAGE, а не физический токен. Нажмите «Найти CSP» после импорта .key.", mbIconInfo)
		return
	}
	// Explicit file selection prevents accidental use of the last token's certificate.
	cert, ok := chooseFile(a.hwnd, false, "Сертификаты (*.cer)\x00*.cer\x00Все файлы (*.*)\x00*.*\x00\x00", "Выберите сертификат, соответствующий выбранному HDIMAGE", "")
	if !ok {
		return
	}
	data, err := os.ReadFile(cert)
	if err != nil || !looksDERCertificate(data) {
		alert("Сертификат", "Файл сертификата не найден или не соответствует DER X.509.", mbIconError)
		return
	}
	if !cspConfirm(a.hwnd, "Установка личного сертификата", fmt.Sprintf("Сертификат:\r\n%s\r\n\r\nКонтейнер:\r\n%s\r\n\r\nУбедитесь, что это соответствующая ключевая пара. Программа вызовет certmgr.exe; это изменит личное хранилище сертификатов пользователя. Продолжить?", cert, dst)) {
		return
	}
	a.startCSPBind(dst, cert)
}

func (a *window) queueCSPResult(r workerResponse) {
	a.workMu.Lock()
	a.pending = &r
	a.workMu.Unlock()
	user32.NewProc("PostMessageW").Call(a.hwnd, uintptr(wmWorkDone), 0, 0)
}
func (a *window) startCSPTransfer(src, dst, cert string) {
	a.busy = true
	setText(a.status, "КриптоПро: копирование токена → HDIMAGE (до 90 секунд)...")
	go func() {
		msg := runCSPTransfer(src, dst, cert)
		a.queueCSPResult(workerResponse{Action: "csp-copy", CSPDetails: msg})
	}()
}
func (a *window) startCSPBind(dst, cert string) {
	a.busy = true
	setText(a.status, "КриптоПро: установка личного сертификата (до 45 секунд)...")
	go func() {
		msg := runCSPBind(dst, cert)
		a.queueCSPResult(workerResponse{Action: "csp-copy", CSPDetails: msg})
	}()
}
func runCSPBind(dst, cert string) string {
	exe, err := cspTool("certmgr")
	if err != nil {
		return "Не удалось найти утилиту установки сертификатов: " + err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := runCSP(ctx, exe, "-inst", "-store", "uMy", "-file", cert, "-cont", dst)
	if !cspSucceeded(out, err) {
		return fmt.Sprintf("Сертификат не подтверждён как установленный.\r\nКонтейнер: %s\r\nОшибка: %v\r\nВывод certmgr:\r\n%s\r\n\r\nИспользуйте мастер «Установить личный сертификат» в КриптоПро CSP.", dst, err, out)
	}
	return fmt.Sprintf("certmgr сообщает об успешном завершении установки сертификата.\r\nКонтейнер: %s\r\n\r\nЭто не подтверждает успешную подпись. Проверьте контейнер и подпишите тестовый документ без подключённого токена.", dst)
}
func runCSPTransfer(src, dst, cert string) string {
	certNote := ""
	if cert == "" {
		if fromToken, er := stageCertificateViaCryptoPro(src); er == nil {
			cert = fromToken
		} else {
			certNote = "Автоматически получить сертификат из источника не удалось: " + truncateCSPOutput(er.Error())
		}
	}
	exe, err := cspTool("csptest")
	if err != nil {
		return err.Error()
	}
	before, beforeErr := snapshotPhysicalCSPFolders()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := runCSP(ctx, exe, "-keycopy", "-contsrc", src, "-contdest", dst)
	if !cspSucceeded(out, err) {
		return fmt.Sprintf("НОВАЯ РАБОЧАЯ КОПИЯ НЕ СОЗДАНА.\r\nИсточник: %s\r\nНазначение: %s\r\nПричина: %v\r\nОтвет csptest:\r\n%s\r\n\r\nЗапрет 0x8009000B означает, что данный контейнер не разрешено копировать штатным CSP. Никаких .key программа не подделывает. Если операция оставила неполный каталог, он не является рабочим контейнером.", src, dst, err, out)
	}
	// Verify that the destination is enumerated by the provider; no fake .key creation.
	names, detail, e := enumerateCSPContainers()
	matched := false
	for _, name := range names {
		if strings.EqualFold(name, dst) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Sprintf("csptest сообщил об успехе, однако новый контейнер %s не обнаружен при повторном перечислении.\r\n%s\r\nОшибка: %s\r\n\r\nАвтоматическая привязка сертификата пропущена во избежание ошибочной связи.", dst, detail, e)
	}
	folderOutcome := newCSPFolderOutcome(before, beforeErr)
	if cert == "" {
		return "НОВЫЙ КОНТЕЙНЕР HDIMAGE обнаружен после копирования: " + dst +
			"\r\n\r\n" + folderOutcome +
			"\r\n\r\n" + certNote + "\r\n\r\n" +
			"Чтобы связать сертификат, нажмите «Найти CSP», выберите НОВЫЙ HDIMAGE и нажмите «Связать .CER». " +
			"Затем проверьте подписание без оригинального токена."
	}
	result := runCSPBind(dst, cert)
	return "НОВЫЙ контейнер HDIMAGE обнаружен после копирования: " + dst + "\r\n\r\n" + folderOutcome + "\r\n" + result
}
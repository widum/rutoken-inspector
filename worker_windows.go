//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// The GUI never loads rtPKCS11ECP.dll. Each PKCS#11 operation executes in a
// separate copy of this executable with --worker, which can be terminated on a
// timeout. This keeps the Win32 message loop responsive if a driver stalls.
type workerResponse struct {
	Action      string         `json:"action"`
	Error       string         `json:"error,omitempty"`
	Devices     []deviceInfo   `json:"devices,omitempty"`
	Readers     []string       `json:"pcsc_readers,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
	Libraries   []string       `json:"libraries,omitempty"`
	Report      *scanReport    `json:"report,omitempty"`
	ZIPText     string         `json:"zip_text,omitempty"`
	CSPNames    []string       `json:"csp_names,omitempty"`
	CSPDetails  string         `json:"csp_details,omitempty"`
	CSPTarget   string         `json:"csp_target,omitempty"`
	CSPCert     string         `json:"csp_cert,omitempty"`
	CertBytes   map[int][]byte `json:"certificates,omitempty"`
	PublicBytes map[int][]byte `json:"public_objects,omitempty"`
	Duration    int64          `json:"duration_ms"`
}

func logPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "RutokenInspector3", "diagnostics.log")
}
func appendLog(msg string) {
	path := logPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\r\n", time.Now().Format("2006-01-02T15:04:05.000"), msg)
}

// For legacy Rutoken S the vendor may install only the 32-bit rtPKCS11.dll.
// Execute PKCS#11 operations in the matching-bitness child, never in the GUI.
func subprocessExecutable(executable, action string, args []string) (string, error) {
	if strconv.IntSize == 32 || (action != "find" && action != "scan" && action != "scan-pin") || len(args) == 0 {
		return executable, nil
	}
	f, err := pe.Open(args[0])
	if err != nil {
		return executable, nil
	}
	machine := f.FileHeader.Machine
	f.Close()
	if machine != pe.IMAGE_FILE_MACHINE_I386 {
		return executable, nil
	}
	if len(legacyWorker) == 0 {
		return "", fmt.Errorf("встроенный 32-битный модуль поиска недоступен")
	}
	sum := sha256.Sum256(legacyWorker)
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "RutokenInspector3", "helpers")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := filepath.Join(dir, fmt.Sprintf("rutoken-worker-x86-%x.exe", sum[:6]))
	if _, err := os.Stat(name); os.IsNotExist(err) {
		tmp := name + ".tmp"
		if err := os.WriteFile(tmp, legacyWorker, 0700); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, name); err != nil {
			os.Remove(tmp)
			return "", err
		}
	}
	appendLog("WORKER: using 32-bit helper for " + filepath.Base(args[0]))
	return name, nil
}

func runSubprocess(executable, action string, timeout time.Duration, secret []byte, args ...string) workerResponse {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r := workerResponse{Action: action}
	f, err := os.CreateTemp("", "rutoken-inspector-*.json")
	if err != nil {
		r.Error = "Не удалось создать временный файл: " + err.Error()
		return r
	}
	resultPath := f.Name()
	_ = f.Close()
	defer os.Remove(resultPath)
	argv := append([]string{"--worker", action, resultPath}, args...)
	runner, chooseErr := subprocessExecutable(executable, action, args)
	if chooseErr != nil {
		r.Error = "Не удалось выбрать рабочий процесс: " + chooseErr.Error()
		return r
	}
	cmd := exec.CommandContext(ctx, runner, argv...)
	if len(secret) > 0 {
		cmd.Stdin = bytes.NewReader(secret)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, runErr := cmd.CombinedOutput()
	data, readErr := os.ReadFile(resultPath)
	if readErr == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &r); err != nil {
			r.Error = "Ошибка JSON рабочего процесса: " + err.Error()
		}
	} else if runErr == nil {
		r.Error = "Рабочий процесс не вернул результат"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		r.Error = fmt.Sprintf("Тайм-аут (%d секунд) при операции %s", int(timeout.Seconds()), action)
	} else if runErr != nil && r.Error == "" {
		r.Error = "Рабочий процесс завершился с ошибкой: " + runErr.Error()
		if len(out) > 0 {
			msg := string(out)
			if len(msg) > 350 {
				msg = msg[:350]
			}
			r.Error += " (" + msg + ")"
		}
	}
	return r
}

func findLibraries(primary string) []string {
	primary = strings.Trim(primary, `" `)
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	system32 := filepath.Join(root, "System32")
	syswow64 := filepath.Join(root, "SysWOW64")
	// ECP first for GOST-enabled devices, then legacy DLL for S/Lite.
	candidates := []string{primary,
		filepath.Join(filepath.Dir(primary), "rtPKCS11ECP.dll"),
		filepath.Join(filepath.Dir(primary), "rtPKCS11.dll"),
		filepath.Join(system32, "rtPKCS11ECP.dll"),
		filepath.Join(system32, "rtPKCS11.dll"),
		filepath.Join(syswow64, "rtPKCS11.dll"),
	}
	var result []string
	seen := map[string]bool{}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		lower := strings.ToLower(path)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			result = append(result, path)
		}
	}
	return result
}

// isLegacyRutokenS determines the known problematic PKCS#11 route.
// In the passive CSP mode, we enumerate keys through CryptoPro instead.
// Never treat a reader label or serial alone as proof that a CSP container
// belongs to this particular token.
func isLegacyRutokenS(d deviceInfo) bool {
	model := strings.ToLower(strings.TrimSpace(d.Model))
	label := strings.ToLower(strings.TrimSpace(d.Label))
	return model == "rutoken s" || strings.HasPrefix(model, "rutoken s ") ||
		strings.HasPrefix(label, "rutoken s ") || label == "rutoken s"
}

func (a *window) startWorker(action string, secret []byte, args ...string) {
	if a.busy {
		setText(a.status, "Операция выполняется, дождитесь завершения.")
		return
	}
	executable, err := os.Executable()
	if err != nil {
		alert("Ошибка", err.Error(), mbIconError)
		return
	}
	a.busy = true
	// Invalidate the previous scan BEFORE launching any new scan. Otherwise a
	// failed PIN scan leaves an old unauthenticated report exportable as new.
	if action == "scan" || action == "scan-pin" || action == "find" || action == "scan-s-csp" {
		a.report = nil
		a.cspStagedCert = "" // Avoid linking a stale certificate after switching token.
		sm(a.list, lbReset, 0, 0)
		setText(a.details, "Предыдущий отчёт сброшен. Выполняется новая проверка.\r\nPIN не сохраняется в отчётах и журнале.")
	}
	setText(a.status, "Выполняется "+action+" в отдельном процессе...")
	appendLog("GUI: start " + action)
	go func() {
		defer clear(secret)
		started := time.Now()
		r := workerResponse{Action: action}
		if action == "csp-list" || action == "scan-s-csp" {
			var names []string
			names, r.CSPDetails, r.Error = enumerateCSPContainers()
			// Present token readers before HDIMAGE so an existing local copy
			// is not silently selected as the source of a transfer.
			ordered, inventory := summarizeCSPInventory(names)
			r.CSPNames = ordered
			if action == "scan-s-csp" {
				// CSP enumeration is global and may include unrelated HDIMAGE
				// or other removable key containers. Do not misattribute them.
				r.CSPDetails = "Рутокен S — безопасная диагностика через КриптоПро.\r\n" +
					"Старый PKCS#11-драйвер не используется: он завершался с ошибкой.\r\n" +
					"PIN не запрашивался. Закрытые ключи не читались.\r\n\r\n" + inventory
			} else {
				r.CSPDetails = inventory + "\r\n\r\n" + r.CSPDetails
			}
		} else if action == "find" {
			if len(args) < 1 {
				r.Error = "Не передан путь библиотеки"
			} else {
				libs := findLibraries(args[0])
				r.Libraries = libs
				var discovered []deviceInfo
				seen := map[string]bool{}
				for _, lib := range libs {
					appendLog("GUI: find library " + lib)
					sub := runSubprocess(executable, "find", 14*time.Second, nil, lib)
					if sub.Error != "" {
						r.Warnings = append(r.Warnings, filepath.Base(lib)+": "+sub.Error)
						continue
					}
					for _, d := range sub.Devices {
						d.Library = lib
						// Keep one preferred (ECP/GOST) view per physical serial. Devices with
						// an empty serial are deliberately NOT merged to avoid losing a token.
						serial := strings.TrimSpace(d.Serial)
						if serial != "" && serial != "00000000" {
							k := strings.ToLower(serial)
							if seen[k] {
								continue
							}
							seen[k] = true
						}
						discovered = append(discovered, d)
					}
				}
				r.Devices = discovered
				// Smart Card reader enumeration uses a separate native Windows API.
				// This also provides evidence for tokens not surfaced via PKCS#11.
				pcsc := runSubprocess(executable, "readers", 7*time.Second, nil)
				if pcsc.Error != "" {
					r.Warnings = append(r.Warnings, "Windows PC/SC: "+pcsc.Error)
				} else {
					r.Readers = pcsc.Readers
				}
				if len(libs) == 0 {
					r.Warnings = append(r.Warnings, "Ни одна PKCS#11 DLL не найдена")
				}
			}
		} else {
			timeout := 20 * time.Second
			if action == "scan" || action == "scan-pin" {
				timeout = 50 * time.Second
			}
			if action == "zip" {
				timeout = 15 * time.Second
			}
			if action == "com-audit" || action == "com-readers" || action == "hardware-csp" {
				timeout = 100 * time.Second // bounded registry queries and two isolated JScript COM probes
			}
			r = runSubprocess(executable, action, timeout, secret, args...)
		}
		r.Duration = time.Since(started).Milliseconds()
		if r.Error != "" {
			appendLog("GUI: failure " + action + " " + r.Error)
		} else {
			appendLog("GUI: completed " + action)
		}
		a.workMu.Lock()
		a.pending = &r
		a.workMu.Unlock()
		user32.NewProc("PostMessageW").Call(a.hwnd, uintptr(wmWorkDone), 0, 0)
	}()
}

func (a *window) workDone() {
	a.workMu.Lock()
	r := a.pending
	a.pending = nil
	a.workMu.Unlock()
	a.busy = false
	if r == nil {
		return
	}
	if r.Error != "" {
		setText(a.status, "Ошибка: "+r.Error+". Предыдущий отчёт недоступен.")
		setText(a.details, "Операция: "+r.Action+"\r\n\r\n"+r.Error+"\r\n\r\nЖурнал: "+logPath()+"\r\n\r\nМожно повторить проверку. Устройство и PIN не изменялись.")
		return
	}
	switch r.Action {
	case "csp-list", "scan-s-csp":
		a.cspNames = r.CSPNames
		sm(a.cspOptions, cbReset, 0, 0)
		for _, name := range r.CSPNames {
			sm(a.cspOptions, cbAddString, 0, uintptr(unsafe.Pointer(u16(name))))
		}
		if len(r.CSPNames) != 0 {
			sm(a.cspOptions, cbSetCurSel, 0, 0)
		}
		if a.page == 3 {
			setText(a.details, r.CSPDetails+"\r\n\r\nКонтейнеры КриптоПро:\r\n"+strings.Join(r.CSPNames, "\r\n"))
		} else {
			var tokenCount, hdCount int
			for _, name := range r.CSPNames {
				if strings.Contains(strings.ToUpper(name), "HDIMAGE") {
					hdCount++
				} else {
					tokenCount++
				}
			}
			summary := fmt.Sprintf("КРИПТОПРО CSP 5\r\n\r\nВсего контейнеров: %d\r\nНа носителях: %d\r\nНа компьютере (HDIMAGE): %d\r\n\r\nВыберите конкретный контейнер в выпадающем списке выше.\r\nЕсли он уже на ПК — перенос не требуется.\r\n\r\n", len(r.CSPNames), tokenCount, hdCount)
			if r.Action == "scan-s-csp" {
				summary += "Рутокен S: используется безопасное перечисление через КриптоПро.\r\n"
			}
			summary += "Совпадение имён токена и HDIMAGE не доказывает совпадения ключевого материала.\r\n\r\nПроверку подписи проводите без физического носителя."
			setText(a.details, summary)
		}
		setText(a.status, fmt.Sprintf("КриптоПро: найдено %d контейнеров", len(r.CSPNames)))
	case "csp-copy":
		// Preserve the full technical output without dumping it in a huge modal
		// MessageBox (which becomes unreadable on scaled Windows 11 desktops).
		a.lastCSPResult = r.CSPDetails
		badState := strings.Contains(strings.ToLower(r.CSPDetails), "0x8009000b")
		failed := strings.Contains(r.CSPDetails, "НЕ подтверждено") ||
			strings.Contains(strings.ToLower(r.CSPDetails), "не удалось") || badState
		if failed {
			setText(a.status, "Копирование не выполнено. Действующие контейнеры не изменены.")
			if badState {
				setText(a.details, "КОПИРОВАНИЕ НЕ ВЫПОЛНЕНО\r\n\r\nКриптоПро отказал в экспорте ключа (0x8009000B).\r\nКонтейнер остался на токене; новая копия для подписи не создана.\r\n\r\nУстановить только сертификат недостаточно для автономной подписи.\r\n\r\nПолный ответ csptest находится в разделе «Диагностика».")
				alert("Копирование отклонено КриптоПро", "Ошибка 0x8009000B: провайдер запретил копирование закрытого ключа.\r\n\r\nНовый HDIMAGE не подтверждён.\r\nПолные подробности — в разделе «Диагностика».", mbIconError)
			} else {
				setText(a.details, "Операция не подтверждена.\r\n\r\nОткройте «Диагностика», чтобы посмотреть полный ответ КриптоПро.\r\nНе устанавливайте сертификат как подтверждение успешного копирования.")
				alert("Операция не выполнена", "КриптоПро не подтвердил копирование.\r\nПолный отчёт сохранён в разделе «Диагностика».", mbIconError)
			}
		} else {
			setText(a.details, r.CSPDetails)
			setText(a.status, "Операция КриптоПро завершена; требуется проверка подписи")
			alert("Операция КриптоПро", "Результат получен. Проверьте контейнер в КриптоПро без подключённого носителя.\r\nПодробности — в разделе «Диагностика».", mbIconInfo)
		}
	case "find":
		a.devs = r.Devices
		a.report = nil
		sm(a.devices, cbReset, 0, 0)
		sm(a.list, lbReset, 0, 0)
		for _, d := range r.Devices {
			s := fmt.Sprintf("%s | %s | %s (слот %d)", d.Model, d.Label, d.Serial, d.Slot)
			sm(a.devices, cbAddString, 0, uintptr(unsafe.Pointer(u16(s))))
		}
		if len(r.Devices) > 0 {
			sm(a.devices, cbSetCurSel, 0, 0)
		}
		a.updateSelectedDevice()
		setText(a.status, fmt.Sprintf("Найдено устройств: %d, время: %d мс", len(r.Devices), r.Duration))
		var lines []string
		lines = append(lines, "Результат поиска Рутокен, включая S и Lite:", "")
		if len(r.Devices) > 0 {
			for _, d := range r.Devices {
				lines = append(lines, fmt.Sprintf("Найден: %s | %s | серийный %s | DLL: %s", d.Model, d.Label, d.Serial, d.Library))
			}
		} else {
			lines = append(lines, "PKCS#11: устройства не найдены")
		}
		lines = append(lines, "", "Проверенные библиотеки:")
		if len(r.Libraries) == 0 {
			lines = append(lines, "не найдены")
		}
		for _, lib := range r.Libraries {
			lines = append(lines, lib)
		}
		lines = append(lines, "", "Считыватели Windows PC/SC (наличие считывателя само по себе не гарантирует наличие токена):")
		if len(r.Readers) == 0 {
			lines = append(lines, "не обнаружены")
		}
		for _, reader := range r.Readers {
			lines = append(lines, reader)
		}
		if len(r.Warnings) > 0 {
			lines = append(lines, "", "Ошибки и предупреждения:")
			lines = append(lines, r.Warnings...)
		}
		lines = append(lines, "", "Рутокен S использует rtPKCS11.dll (не rtPKCS11ECP.dll). Если Windows видит считыватель, но нет устройства в PKCS#11 — проверьте драйвер S и разрядность DLL. КриптоПро CSP 5.x может обнаруживать S в пассивном режиме через CryptoAPI независимо от PKCS#11.")
		if a.page == 3 {
			setText(a.details, strings.Join(lines, "\r\n"))
		} else {
			var summary []string
			summary = append(summary, fmt.Sprintf("ПОДКЛЮЧЁННЫЕ УСТРОЙСТВА: %d", len(r.Devices)), "")
			for i, d := range r.Devices {
				summary = append(summary, fmt.Sprintf("%d. %s    •    серийный %s", i+1, d.Model, d.Serial))
			}
			if len(r.Devices) == 0 {
				summary = append(summary, "PKCS#11 не обнаружил подключённых токенов.")
			}
			summary = append(summary, "", "Нажмите «Обновить список» для поиска контейнеров КриптоПро.",
				"Для файловых резервных копий откройте «Установить копию».",
				"Полный технический журнал доступен в разделе «Диагностика».")
			if len(r.Warnings) > 0 {
				summary = append(summary, "", fmt.Sprintf("Предупреждений драйверов: %d (не обязательно мешают работе CSP).", len(r.Warnings)))
			}
			setText(a.details, strings.Join(summary, "\r\n"))
		}
	case "scan", "scan-pin":
		a.report = r.Report
		if a.report != nil {
			for i, b := range r.CertBytes {
				if i >= 0 && i < len(a.report.Objects) && a.report.Objects[i].Class == "Сертификат" {
					a.report.Objects[i].Cert = b
				}
			}
			for i, b := range r.PublicBytes {
				if i >= 0 && i < len(a.report.Objects) && (a.report.Objects[i].Class == "Открытый ключ" || a.report.Objects[i].Class == "Объект данных") && a.report.Objects[i].DataRead == "ok" {
					a.report.Objects[i].PublicData = b
				}
			}
		}
		if r.Report == nil {
			setText(a.status, "Пустой отчёт сканирования")
			return
		}
		sm(a.list, lbReset, 0, 0)
		for _, obj := range r.Report.Objects {
			s := obj.Class + " | " + obj.Label
			sm(a.list, lbAddString, 0, uintptr(unsafe.Pointer(u16(s))))
		}
		privateCount := 0
		for _, obj := range r.Report.Objects {
			if obj.Class == "Закрытый ключ" {
				privateCount++
			}
		}
		authText := "НЕТ (без PIN)"
		if r.Report.Authenticated {
			authText = "ДА (C_Login выполнен успешно)"
		}
		info := fmt.Sprintf("Устройство: %s\r\nСлот: %d\r\nРежим: %s\r\nАутентификация: %s\r\nВремя отчёта (UTC): %s\r\n\r\nОбъектов: %d\r\nИз них закрытых ключей: %d\r\nОшибок: %d\r\nВремя: %d мс\r\n\r\nВыберите объект слева.\r\nЧтение значения закрытого ключа отключено.", r.Report.Token.Model, r.Report.Token.Slot, r.Report.Mode, authText, r.Report.ScanAtUTC, len(r.Report.Objects), privateCount, len(r.Report.Errors), r.Duration)
		if r.Report.Authenticated && privateCount == 0 {
			info += "\r\n\r\nПримечание: авторизация успешна, но в доступном списке PKCS#11 закрытых ключей нет. Это не доказывает отсутствие ключа на носителе."
		}
		if len(r.Report.Errors) > 0 {
			info += "\r\n\r\n" + strings.Join(r.Report.Errors, "\r\n")
		}
		setText(a.details, info)
		setText(a.status, fmt.Sprintf("Готово [%s]: %d объектов, %d закрытых ключей, %d ошибок, %d мс", authText, len(r.Report.Objects), privateCount, len(r.Report.Errors), r.Duration))
	case "com-audit", "com-readers", "hardware-csp":
		setText(a.details, r.CSPDetails)
		setText(a.status, "Проверка COM Lite завершена (без доступа к ключам)")
	case "zip":
		setText(a.details, r.ZIPText)
		setText(a.status, fmt.Sprintf("Архив проанализирован за %d мс", r.Duration))
	}
}
func workerMain(args []string) {
	// Result is written to a temp file because GUI-subsystem executables do not
	// reliably have a console/valid standard output handles on Windows.
	if len(args) < 2 {
		return
	}
	action, resultPath := args[0], args[1]
	started := time.Now()
	r := workerResponse{Action: action}
	defer func() {
		if v := recover(); v != nil {
			r.Error = fmt.Sprintf("Сбой рабочего процесса: %v", v)
			appendLog("WORKER: panic " + action)
		}
		r.Duration = time.Since(started).Milliseconds()
		b, err := json.Marshal(r)
		if err == nil {
			_ = os.WriteFile(resultPath, b, 0600)
		}
	}()
	appendLog("WORKER: begin " + action)
	switch action {
	case "com-audit":
		r.CSPDetails = auditCOMEnvironment()
	case "com-readers":
		r.CSPDetails = auditCOMReaders()
	case "hardware-csp":
		r.CSPDetails = auditDeviceAndCSP()
	case "readers":
		r.Readers, r.Error = listPCSCReaders()
	case "find", "scan", "scan-pin":
		if len(args) < 3 {
			r.Error = "Не передан путь библиотеки"
			return
		}
		lib := args[2]
		if _, err := os.Stat(lib); err != nil {
			r.Error = "Библиотека PKCS#11 не найдена: " + err.Error()
			return
		}
		appendLog("WORKER: opening PKCS11")
		p, err := openPKCS(lib)
		if err != nil {
			r.Error = err.Error()
			return
		}
		defer p.close()
		appendLog("WORKER: reading slot list")
		devices, err := p.slots()
		if err != nil {
			r.Error = err.Error()
			return
		}
		if action == "find" {
			r.Devices = devices
			return
		}
		if len(args) < 4 {
			r.Error = "Не указан слот"
			return
		}
		chosenSlot, err := strconv.ParseUint(args[3], 10, 32)
		if err != nil {
			r.Error = "Некорректный номер слота"
			return
		}
		var d *deviceInfo
		for i := range devices {
			if devices[i].Slot == uint32(chosenSlot) {
				d = &devices[i]
				break
			}
		}
		if d == nil {
			r.Error = "Устройство отключено или сменило слот; выполните поиск заново"
			return
		}
		appendLog("WORKER: opening read-only session")
		var pin []byte
		if action == "scan-pin" {
			// PIN is delivered exclusively over the child's stdin pipe. It does not
			// appear in command-line arguments, JSON reports, or diagnostics logs.
			pin, err = io.ReadAll(io.LimitReader(os.Stdin, 129))
			if err != nil || len(pin) == 0 || len(pin) > 128 {
				r.Error = "PIN должен содержать от 1 до 128 байт"
				clear(pin)
				return
			}
			defer clear(pin)
		}
		report, err := p.scan(*d, pin)
		if err != nil {
			r.Error = err.Error()
			return
		}
		r.Report = report
		for i, item := range report.Objects {
			if len(item.Cert) > 0 {
				if r.CertBytes == nil {
					r.CertBytes = make(map[int][]byte)
				}
				r.CertBytes[i] = item.Cert
			}
			if item.DataRead == "ok" {
				if r.PublicBytes == nil {
					r.PublicBytes = make(map[int][]byte)
				}
				r.PublicBytes[i] = item.PublicData
			}
		}
	case "zip":
		if len(args) < 3 {
			r.Error = "Не указан архив"
			return
		}
		r.ZIPText, r.Error = analyzeZipText(args[2])
	default:
		r.Error = "Неизвестная операция"
	}
}
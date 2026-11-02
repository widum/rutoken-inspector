//go:build windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// auditCOMEnvironment checks registered components and whether the
// JScript/WSH runtime can instantiate the COM context itself.
// No calls to vendor token APIs, key operations or PIN interactions occur.
func auditCOMEnvironment() string {
	type cls struct{ progid, title string }
	classes := []cls{
		{"rtCOMLite.rtContext", "Rutoken COM Lite"},
		{"ADODB.Stream", "ADO Stream (двоичные потоки)"},
		{"Scripting.FileSystemObject", "Windows Script Host (файлы)"},
		{"Shell.Application", "Windows Shell"},
		{"CAPICOM.Store", "CAPICOM (сертификаты)"},
	}
	var b strings.Builder
	b.WriteString("RUTOKEN COM LITE — ПРОВЕРКА ЧЕРЕЗ WINDOWS SCRIPT HOST (JSCRIPT)\r\n")
	b.WriteString("Диагностика только создаёт COM-контекст. Не запрашивает PIN, не читает ключи или сертификаты.\r\n")
	b.WriteString("Не изменяет Crypto Pro, токен или реестр.\r\n\r\n")
	for _, c := range classes {
		b.WriteString("• " + c.title + "\r\n")
		for _, arch := range []string{"32", "64"} {
			b.WriteString(fmt.Sprintf("    COM %s-bit: %s\r\n", arch, queryCOMRegistration(c.progid, arch)))
		}
	}
	b.WriteString("\r\nФАКТИЧЕСКИЙ ЗАПУСК ЧЕРЕЗ CSCRIPT/JSCRIPT (НЕ POWERSHELL):\r\n")
	for _, arch := range []string{"32", "64"} {
		begin := time.Now()
		result := probeCOMLiteActivation(arch)
		b.WriteString(fmt.Sprintf("  %s-bit: %s (%.1f с)\r\n", arch, result, time.Since(begin).Seconds()))
	}
	b.WriteString("\r\nУСТАНОВЛЕННЫЕ КОМПОНЕНТЫ:\r\n")
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	paths := []string{
		filepath.Join(root, "SysWOW64", "rtPKCS11.dll"),
		filepath.Join(root, "System32", "rtPKCS11ECP.dll"),
		filepath.Join(os.Getenv("ProgramFiles"), "Crypto Pro", "CSP", "csptest.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Crypto Pro", "CSP", "csptest.exe"),
	}
	for _, p := range paths {
		if p == "" || strings.HasPrefix(p, string(filepath.Separator)) {
			continue
		}
		status := "не найден"
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			status = "найден"
		}
		b.WriteString(fmt.Sprintf("  %s: %s\r\n", status, p))
	}
	b.WriteString("\r\nКАК ЧИТАТЬ РЕЗУЛЬТАТ:\r\n")
	b.WriteString("«COM создан»: JScript смог запустить rtCOMLite.rtContext в этой разрядности.\r\n")
	b.WriteString("«Нет вывода»: скрипт не вернул ожидаемых маркеров; результат COM неизвестен.\r\n")
	b.WriteString("«Зависание COM»: JScript запустился, но создание объекта не завершилось.\r\n")
	b.WriteString("«Зависание WSH»: сам cscript не успел вывести стартовый маркер.\r\n")
	b.WriteString("COM-активация НЕ подтверждает связь с Рутокеном или возможность копирования ключа.\r\n")
	return b.String()
}

func queryCOMRegistration(progid, arch string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	path := `HKCR\` + progid + `\CLSID`
	cmd := exec.CommandContext(ctx, "reg.exe", "query", path, "/ve", "/reg:"+arch)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "тайм-аут чтения реестра"
	}
	if err != nil {
		return "не найдена регистрация (или нет доступа)"
	}
	if !bytes.Contains(bytes.ToUpper(out), []byte("REG_SZ")) {
		return "ключ найден, но CLSID не подтверждён"
	}
	return "найдена"
}

// Unlike Windows PowerShell (used in v2.7), the Windows Script Host runs a
// native JScript engine. This matches the scripting environment of the
// the COM scripting runtime without PowerShell startup latency.
// IMPORTANT: Do not pass //B: it suppresses WScript.Echo output, hiding
// the very status markers that the Go parent needs to classify the result.
// The script is deliberately fixed and can ONLY instantiate and release the
// known context object. It does not read token data or invoke COM methods.
const comProbeScript = `WScript.Echo("WSH_STARTED");
var obj = null;
try {
    obj = new ActiveXObject("rtCOMLite.rtContext");
    if (obj == null) {
        WScript.Echo("COM_NULL");
        WScript.Quit(3);
    }
    WScript.Echo("COM_CREATED");
    obj = null;
    WScript.Echo("COM_EXITING");
} catch (e) {
    var n = (typeof e.number == "number") ? (e.number >>> 0) : 0;
    var hex = ("00000000" + n.toString(16)).slice(-8).toUpperCase();
    WScript.Echo("COM_ERR_0X" + hex);
    WScript.Quit(2);
}
`

const comProbeTimeout = 20 * time.Second

// Use //I explicitly to avoid any previously persisted batch-mode setting.
// We do not display UI: cscript is launched with a hidden window and its
// stdout/stderr are collected. The fixed script catches its own COM errors.
func comProbeHostArgs(scriptPath string) []string {
	return []string{"//Nologo", "//I", "//E:JScript", scriptPath}
}

func probeCOMLiteActivation(arch string) string {
	if arch != "32" && arch != "64" {
		return "неподдерживаемая архитектура"
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	winDir := "System32"
	if arch == "32" {
		winDir = "SysWOW64"
	}
	host := filepath.Join(root, winDir, "cscript.exe")
	if st, err := os.Stat(host); err != nil || st.IsDir() {
		return "Windows Script Host (cscript.exe) не найден"
	}
	scriptFile, err := os.CreateTemp("", "ri-com-test-*.js")
	if err != nil {
		return "не удалось подготовить временный тест WSH"
	}
	scriptPath := scriptFile.Name()
	defer os.Remove(scriptPath)
	if _, err = scriptFile.WriteString(comProbeScript); err != nil {
		scriptFile.Close()
		return "не удалось записать временный тест WSH"
	}
	if err = scriptFile.Close(); err != nil {
		return "не удалось закрыть временный тест WSH"
	}

	ctx, cancel := context.WithTimeout(context.Background(), comProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, host, comProbeHostArgs(scriptPath)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = nil
	raw, runErr := cmd.CombinedOutput()
	return formatCOMJScriptResult(raw, runErr, ctx.Err() != nil)
}

func formatCOMJScriptResult(raw []byte, cmdErr error, timedOut bool) string {
	// Read only explicit ASCII markers. Never leak arbitrary COM output.
	out := strings.ToUpper(string(raw))
	if timedOut {
		if strings.Contains(out, "COM_CREATED") {
			return "COM создан, но процесс завис при завершении (20 с)"
		}
		if strings.Contains(out, "WSH_STARTED") {
			return "зависание при создании COM-объекта (20 с)"
		}
		return "тайм-аут запуска Windows Script Host (20 с); COM не проверен"
	}
	if i := strings.Index(out, "COM_ERR_0X"); i >= 0 {
		suffix := out[i+len("COM_ERR_0X"):]
		var code strings.Builder
		for _, c := range suffix {
			if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') {
				code.WriteRune(c)
			} else {
				break
			}
			if code.Len() == 8 {
				break
			}
		}
		if code.Len() == 8 {
			return "COM не запускается (HRESULT 0x" + code.String() + ")"
		}
	}
	if strings.Contains(out, "COM_NULL") {
		return "COM вернул пустой объект"
	}
	if strings.Contains(out, "COM_CREATED") && cmdErr == nil {
		return "успешно: COM-объект создан, процесс завершён"
	}
	if cmdErr != nil {
		if strings.Contains(out, "WSH_STARTED") {
			return fmt.Sprintf("JScript запустился, но завершился с ошибкой (%v)", cmdErr)
		}
		return fmt.Sprintf("не удалось запустить JScript (%v)", cmdErr)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "Windows Script Host завершился без вывода (нет маркеров); проверьте ограничения JScript/WSH"
	}
	// The script never reads token data. Showing a short cleaned error helps
	// troubleshoot unsupported/disabled JScript without dumping arbitrary data.
	trimmed := strings.Join(strings.Fields(string(raw)), " ")
	runes := []rune(trimmed)
	if len(runes) > 180 {
		trimmed = string(runes[:180]) + "…"
	}
	return "неизвестный ответ Windows Script Host: " + trimmed
}